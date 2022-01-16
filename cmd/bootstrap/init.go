package bootstrap

import (
	"archive/zip"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	initDesc    = ``
	initExample = ``
)

type initCmd struct {
	chaincode   string
	language    string
	destination string
}

func (c initCmd) validate() error {
	if c.chaincode == "" {
		return errors.New("--chaincode is required")
	}
	if c.language == "" {
		return errors.New("--language is required")
	}
	if c.destination == "" {
		return errors.New("--chaincode is required")
	}
	return nil
}

func (c initCmd) run() error {
	var err error
	zipUrl := "https://github.com/kfsoftware/externalbuilder/archive/refs/heads/main.zip"
	resp, err := http.Get(zipUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	zipFileDest, err := ioutil.TempFile(os.TempDir(), "prefix")
	if err != nil {
		log.Fatal(err)
	}
	defer zipFileDest.Close()
	_, err = io.Copy(zipFileDest, resp.Body)
	if err != nil {
		return err
	}
	reader, err := zip.OpenReader(zipFileDest.Name())
	if err != nil {
		return err
	}
	err = c.unzip(reader, err)
	if err != nil {
		return err
	}
	return nil
}

func (c initCmd) unzip(reader *zip.ReadCloser, err error) error {
	for _, f := range reader.File {
		// github ZIP returns the zip with a folder inside
		chunks := strings.SplitN(f.Name, "/", 2)
		filePath := filepath.Join(c.destination, chunks[1])

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(filePath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return err
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			return err
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}

func NewInitCmd() *cobra.Command {
	c := &initCmd{}
	cmd := &cobra.Command{
		Use:     "init",
		Short:   "Init a chaincode",
		Long:    initDesc,
		Example: initExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			viper.AutomaticEnv()
			err = viper.BindEnv("")
			if err != nil {
				return nil
			}
			viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.chaincode, "chaincode", "", "chaincode name within the channel")
	f.StringVar(&c.language, "language", "", "programming language of the chaincode")
	f.StringVar(&c.destination, "dest", "", "destination folder")
	return cmd
}
