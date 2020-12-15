package cmd

import (
	"debug/pe"
	log "github.com/sirupsen/logrus"
)

type chunk struct {
	chunkType   string
	minCaveSize int
	imageBase   uint32
	section     *pe.Section
	testBase    byte
	count       uint32
	pos         uint32
}

type nullChunk struct {
	chunk
}

func NewNullChunk(minCaveSize int, imageBase uint32, section *pe.Section) *nullChunk {
	result := nullChunk{}
	result.chunkType = "NULL"
	result.testBase = 0x00
	result.minCaveSize = minCaveSize
	result.imageBase = imageBase
	result.section = section
	return &result
}

type nopChunk struct {
	chunk
}

func NewNopChunk(minCaveSize int, imageBase uint32, section *pe.Section) *nopChunk {
	result := nopChunk{}
	result.chunkType = "NOP"
	result.testBase = 0x90
	result.minCaveSize = minCaveSize
	result.imageBase = imageBase
	result.section = section
	return &result
}

func (c *chunk) checkbyte(b byte) {
	if b == c.testBase {
		c.count++
	} else {
		if c.count > uint32(c.minCaveSize) {
			log.Infof("\t%d bytes\tat: (Raw Address: 0x%08x \tVirtual Address: 0x%08x)", c.count,
				c.pos - c.count, c.imageBase + c.section.VirtualAddress + c.pos - c.count)
		}
		c.count = 0
	}
	c.pos++
}

func (c *chunk) isEmpty() bool {
	return c.count == c.pos
}
