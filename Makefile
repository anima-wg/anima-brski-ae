SHELL=bash # This is needed because of a problem in "build" rule; good for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-async-enroll

html: xml
	@xml2rfc ${DRAFT}.xml --html

xml:
	@kdrfc ${DRAFT}.md

clean:
	@rm -f ${DRAFT}.{txt,xml,html}
