package cmd

import (
	"debug/pe"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

var rootCmd = &cobra.Command{
	Use:   "gocave",
	Short: "Find code caves in PE files of given length",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := cobra.MarkFlagRequired(cmd.Flags(), "file")
		if err != nil {
			log.Fatal("Missing file flag")
		}

		fileName, err := cmd.Flags().GetString("file")
		minCaveSize, err := cmd.Flags().GetInt("size")
		imageBase, err := cmd.Flags().GetUint32("base")

		file := ioReader(fileName)
		f, err := pe.NewFile(file)
		if err != nil {
			log.Fatal(err)
		}

		var IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE uint16 = 0x0040 // for compatibility reasons, we don't use the constant located in debug/pe
		isAslr := f.Characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

		log.Infof("Looking for code caves in %s", fileName)
		log.Infof("Image Base: 0x%08x", imageBase)
		log.Infof("Looking for code caves of minimum %d bytes", minCaveSize)
		if isAslr > 0 {
			log.Warn("ASL is enabled. Virtual Address might be different once loaded in memory.")
		}

		for _, section := range f.Sections {
			log.Infof("Parsing section %s", section.Name)
			data, err := section.Data()
			if err != nil {
				log.Fatal(err)
			}

			var count uint32
			var pos uint32
			for _, b := range data {
				if b == 0x00 {
					count++
				} else {
					if count > uint32(minCaveSize) {
						log.Infof("Cave of %d bytes found in %s at: (Raw Address: 0x%08x, Virtual Address: 0x%08x)", count, section.Name, pos - count, imageBase + section.VirtualAddress + pos - count)
					}
					count = 0
				}
				pos++
			}

			if pos == count {
				log.Infof("Section %s appears to be empty", section.Name)
				log.Infof("Cave of %d bytes found in %s at: (Raw Address: 0x%08x, Virtual Address: 0x%08x)", count, section.Name, pos - count, imageBase + section.VirtualAddress)
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("file", "f", "", "PE File to analyze")
	rootCmd.Flags().IntP("size", "s", 300, "Minimal size of code cave")
	rootCmd.Flags().Uint32P("base", "b", 0x00400000, "Base address")
}
