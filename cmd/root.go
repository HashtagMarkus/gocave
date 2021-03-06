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

func HandleError(err error, message string, fatal bool) {
	if err != nil {
		if fatal {
			log.Fatal(err, message)
		} else {
			log.Error(err, message)
		}
	}
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
		HandleError(err, "Failed to get 'file' parameter", true)
		minCaveSize, err := cmd.Flags().GetInt("size")
		HandleError(err, "Failed to get 'size' parameter", true)
		imageBase, err := cmd.Flags().GetUint32("base")
		HandleError(err, "Failed to get 'base' parameter", true)

		file := ioReader(fileName)
		f, err := pe.NewFile(file)
		HandleError(err, "Could not create PE file", true)

		// for compatibility reasons, we don't use the constant located in debug/pe
		var IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE uint16 = 0x0040
		isAslr := f.Characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

		log.Infof("Looking for code caves in %s", fileName)
		log.Infof("Image Base: 0x%08x", imageBase)
		log.Infof("Looking for code caves of minimum %d bytes", minCaveSize)
		if isAslr > 0 {
			log.Warn("ASL is enabled. Virtual Address might be different once loaded in memory.")
		}

		for _, section := range f.Sections {
			printSectionInformation(section)
			data, err := section.Data()
			HandleError(err, "Could not read Data section " + section.Name + " of PE file", false)

			nullChunk := NewNullChunk(minCaveSize, imageBase, section)
			nopChunk := NewNopChunk(minCaveSize, imageBase, section)

			for _, b := range data {
				nullChunk.checkbyte(b)
				nopChunk.checkbyte(b)
			}

			// Doing this to trigger report if last byte is null or nop byte
			nullChunk.checkbyte(0x90)
			nopChunk.checkbyte(0x00)

			if nullChunk.isEmpty() {
				log.Infof("Section %s appears to be empty", section.Name)
				log.Infof("Cave of %d bytes found in %s at: (Raw Address: 0x%08x, Virtual Address: 0x%08x)",
					nullChunk.count, section.Name, nullChunk.pos - nullChunk.count, imageBase + section.VirtualAddress)
			}
		}
	},
}

func printSectionInformation(section *pe.Section) {
	characteristics := section.Characteristics

	rwx := ""

	var IMAGE_SCN_MEM_EXECUTE uint32 = 0x20000000
	var IMAGE_SCN_MEM_READ uint32 = 0x40000000
	var IMAGE_SCN_MEM_WRITE uint32 = 0x80000000
	if characteristics& IMAGE_SCN_MEM_READ == IMAGE_SCN_MEM_READ {
		rwx += "r"
	}
	if characteristics& IMAGE_SCN_MEM_WRITE == IMAGE_SCN_MEM_WRITE {
		rwx += "w"
	}
	if characteristics& IMAGE_SCN_MEM_EXECUTE == IMAGE_SCN_MEM_EXECUTE {
		rwx += "x"
	}

	log.Infof("# Parsing section %s (%s)", section.Name, rwx)
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
