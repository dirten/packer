package googlecomputeimport

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/storage/v1"

	"github.com/hashicorp/packer/builder/googlecompute"
	"github.com/hashicorp/packer/common"
	"github.com/hashicorp/packer/helper/config"
	"github.com/hashicorp/packer/helper/multistep"
	"github.com/hashicorp/packer/packer"
	"github.com/hashicorp/packer/post-processor/compress"
	"github.com/hashicorp/packer/template/interpolate"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

type Config struct {
	common.PackerConfig `mapstructure:",squash"`

	Bucket              string            `mapstructure:"bucket"`
	GCSObjectName       string            `mapstructure:"gcs_object_name"`
	ImageDescription    string            `mapstructure:"image_description"`
	ImageFamily         string            `mapstructure:"image_family"`
	ImageLabels         map[string]string `mapstructure:"image_labels"`
	ImageName           string            `mapstructure:"image_name"`
	ProjectId           string            `mapstructure:"project_id"`
	AccountFile         string            `mapstructure:"account_file"`
	KeepOriginalImage   bool              `mapstructure:"keep_input_artifact"`
	ServiceAccountEmail string            `mapstructure:"service_account_email"`
	SkipClean           bool              `mapstructure:"skip_clean"`

	ctx     interpolate.Context
	Account googlecompute.AccountFile
}

type PostProcessor struct {
	config Config
	runner multistep.Runner
}

func (p *PostProcessor) Configure(raws ...interface{}) error {
	err := config.Decode(&p.config, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &p.config.ctx,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{
				"gcs_object_name",
			},
		},
	}, raws...)
	if err != nil {
		return err
	}

	// Set defaults
	if p.config.GCSObjectName == "" {
		p.config.GCSObjectName = "packer-import-{{timestamp}}.tar.gz"
	}

	errs := new(packer.MultiError)

	// Check and render gcs_object_name
	if err = interpolate.Validate(p.config.GCSObjectName, &p.config.ctx); err != nil {
		errs = packer.MultiErrorAppend(
			errs, fmt.Errorf("Error parsing gcs_object_name template: %s", err))
	}

	templates := map[string]*string{
		"bucket":       &p.config.Bucket,
		"image_name":   &p.config.ImageName,
		"project_id":   &p.config.ProjectId,
		"account_file": &p.config.AccountFile,
	}
	for key, ptr := range templates {
		if *ptr == "" {
			errs = packer.MultiErrorAppend(
				errs, fmt.Errorf("%s must be set", key))
		}
	}

	if len(errs.Errors) > 0 {
		return errs
	}

	return nil
}

func (p *PostProcessor) PostProcess(ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, error) {
	var err error

	if artifact.BuilderId() != compress.BuilderId {
		err = fmt.Errorf(
			"incompatible artifact type: %s\nCan only import from Compress post-processor artifacts",
			artifact.BuilderId())
		return nil, false, err
	}

	p.config.GCSObjectName, err = interpolate.Render(p.config.GCSObjectName, &p.config.ctx)
	if err != nil {
		return nil, false, fmt.Errorf("Error rendering gcs_object_name template: %s", err)
	}

	rawImageGcsPath, err := p.UploadToBucket(ui, artifact, p.config.Bucket, p.config.GCSObjectName)
	if err != nil {
		return nil, p.config.KeepOriginalImage, err
	}

	gceImageArtifact, err := p.CreateGceImage(ui, p.config.ProjectId, rawImageGcsPath, p.config.ImageName, p.config.ImageDescription, p.config.ImageFamily, p.config.ImageLabels)
	if err != nil {
		return nil, p.config.KeepOriginalImage, err
	}

	if !p.config.SkipClean {
		err = p.DeleteFromBucket(ui, p.config.Bucket, p.config.GCSObjectName)
		if err != nil {
			return nil, p.config.KeepOriginalImage, err
		}
	}

	return gceImageArtifact, p.config.KeepOriginalImage, nil
}

func (p *PostProcessor) UploadToBucket(ui packer.Ui, artifact packer.Artifact, bucket string, gcsObjectName string) (string, error) {
	driverScopes := []string{"https://www.googleapis.com/auth/devstorage.full_control"}
	client, err := p.getClient(driverScopes)
	if err != nil {
		return "", err
	}

	service, err := storage.New(client)
	if err != nil {
		return "", err
	}

	ui.Say("Looking for tar.gz file in list of artifacts...")
	source := ""
	for _, path := range artifact.Files() {
		ui.Say(fmt.Sprintf("Found artifact %v...", path))
		if strings.HasSuffix(path, ".tar.gz") {
			source = path
			break
		}
	}

	if source == "" {
		return "", fmt.Errorf("No tar.gz file found in list of articats")
	}

	artifactFile, err := os.Open(source)
	if err != nil {
		err := fmt.Errorf("error opening %v", source)
		return "", err
	}

	ui.Say(fmt.Sprintf("Uploading file %v to GCS bucket %v/%v...", source, bucket, gcsObjectName))
	storageObject, err := service.Objects.Insert(bucket, &storage.Object{Name: gcsObjectName}).Media(artifactFile).Do()
	if err != nil {
		ui.Say(fmt.Sprintf("Failed to upload: %v", storageObject))
		return "", err
	}

	return "https://storage.googleapis.com/" + bucket + "/" + gcsObjectName, nil
}

func (p *PostProcessor) CreateGceImage(ui packer.Ui, project string, rawImageURL string, imageName string, imageDescription string, imageFamily string, imageLabels map[string]string) (packer.Artifact, error) {
	driverScopes := []string{"https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.full_control"}
	client, err := p.getClient(driverScopes)
	if err != nil {
		return nil, err
	}
	service, err := compute.New(client)
	if err != nil {
		return nil, err
	}

	gceImage := &compute.Image{
		Name:        imageName,
		Description: imageDescription,
		Family:      imageFamily,
		Labels:      imageLabels,
		RawDisk:     &compute.ImageRawDisk{Source: rawImageURL},
		SourceType:  "RAW",
	}

	ui.Say(fmt.Sprintf("Creating GCE image %v...", imageName))
	op, err := service.Images.Insert(project, gceImage).Do()
	if err != nil {
		ui.Say("Error creating GCE image")
		return nil, err
	}

	ui.Say("Waiting for GCE image creation operation to complete...")
	for op.Status != "DONE" {
		op, err = service.GlobalOperations.Get(project, op.Name).Do()
		if err != nil {
			return nil, err
		}

		time.Sleep(5 * time.Second)
	}

	// fail if image creation operation has an error
	if op.Error != nil {
		var imageError string
		for _, error := range op.Error.Errors {
			imageError += error.Message
		}
		err = fmt.Errorf("failed to create GCE image %s: %s", imageName, imageError)
		return nil, err
	}

	return &Artifact{paths: []string{op.TargetLink}}, nil
}

func (p *PostProcessor) DeleteFromBucket(ui packer.Ui, bucket string, gcsObjectName string) error {
	driverScopes := []string{"https://www.googleapis.com/auth/devstorage.full_control"}
	client, err := p.getClient(driverScopes)
	if err != nil {
		return nil
	}

	service, err := storage.New(client)
	if err != nil {
		return nil
	}

	ui.Say(fmt.Sprintf("Deleting import source from GCS %s/%s...", bucket, gcsObjectName))
	err = service.Objects.Delete(bucket, gcsObjectName).Do()
	if err != nil {
		ui.Say(fmt.Sprintf("Failed to delete: %v/%v", bucket, gcsObjectName))
		return err
	}

	return nil
}

func (p *PostProcessor) getClient(driverScopes []string) (*http.Client, error) {
	var client *http.Client
	if p.config.Account.PrivateKey != "" {
		// Auth with AccountFile first if provided
		conf := jwt.Config{
			Email:      p.config.Account.ClientEmail,
			PrivateKey: []byte(p.config.Account.PrivateKey),
			Scopes:     driverScopes,
			TokenURL:   "https://accounts.google.com/o/oauth2/token",
		}

		// Initiate an http.Client. The following GET request will be
		// authorized and authenticated on the behalf of
		// your service account.
		client = conf.Client(oauth2.NoContext)
		return client, nil
	} else {
		// The DefaultClient uses the DefaultTokenSource of the google lib.
		// The DefaultTokenSource uses the "Application Default Credentials"
		// It looks for credentials in the following places, preferring the first location found:
		// 1. A JSON file whose path is specified by the
		//    GOOGLE_APPLICATION_CREDENTIALS environment variable.
		// 2. A JSON file in a location known to the gcloud command-line tool.
		//    On Windows, this is %APPDATA%/gcloud/application_default_credentials.json.
		//    On other systems, $HOME/.config/gcloud/application_default_credentials.json.
		// 3. On Google App Engine it uses the appengine.AccessToken function.
		// 4. On Google Compute Engine and Google App Engine Managed VMs, it fetches
		//    credentials from the metadata server.
		//    (In this final case any provided scopes are ignored.)
		client, err := google.DefaultClient(oauth2.NoContext, driverScopes...)
		if err != nil {
			return nil, err
		}
		return client, nil
	}
	return nil, fmt.Errorf("Something went wrong getting the client for the GCE import post-processor")
}
