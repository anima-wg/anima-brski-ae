SHELL=bash # This is needed because of a problem in "build" rule; good for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-async-enroll
VERSION:=$(shell ./getver ${DRAFT}.md )

.phony: default generate commit

default: ${DRAFT}-${VERSION}.txt

.PRECIOUS: ${DRAFT}.xml

generate:
	kdrfc --v3 -h -t ${DRAFT}.md

# produces also .xml and .html:
%.txt: %.md
	$(MAKE) generate

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

commit: generate
	@git commit ${DRAFT}-??.txt ${DRAFT}.{txt,xml,html} \
	   -m "CI - ietf-draft-files (xml, txt, html) updated" \
	   || echo "No changes to commit"
	@git push -u origin

clean:
	@git checkout -- ${DRAFT}-??.txt ${DRAFT}.{txt,xml,html}
