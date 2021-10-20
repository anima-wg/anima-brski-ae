SHELL=bash # This is needed because of a problem in "build" rule; good for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-async-enroll
VERSION:=$(shell ./getver ${DRAFT}.md )

html: xml
	@xml2rfc ${DRAFT}.xml --html

xml:
	@kdrfc ${DRAFT}.md

version:
	@echo Version: ${VERSION}

clean:
	@rm -f ${DRAFT}.{txt,xml,html}
