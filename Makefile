SHELL=bash # This is needed because of a problem in "build" rule; good for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-async-enroll
VERSION:=$(shell ./getver ${DRAFT}.md )

.phony: default

default: ${DRAFT}-${VERSION}.txt

.PRECIOUS: ${DRAFT}.xml

# produces also .xml and .html:
%.txt: %.md
	kdrfc --v3 -h -t $?

# not needed:
%.xml: %.md
	kdrfc --v3 -x $?

# not needed:
%.txt: %.xml
	xml2rfc --text -o $@ $?

# not needed:
%.html: %.xml
	xml2rfc --html -o $@ $?

${DRAFT}-${VERSION}.txt: ${DRAFT}.txt
	@cp -a ${DRAFT}.txt ${DRAFT}-${VERSION}.txt

version:
	@echo Version: ${VERSION}

clean:
	@git checkout -- ${DRAFT}-??.txt ${DRAFT}.{txt,xml,html}
