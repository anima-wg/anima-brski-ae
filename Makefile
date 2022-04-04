DRAFT:=draft-ietf-anima-brski-ae

all: ${DRAFT}.txt ${DRAFT}.html ${DRAFT}.pdf

%.xml: %.md
	kdrfc --v3 -x $?

%.txt: %.xml
	xml2rfc --text -o $@ $?

%.html: %.xml
	xml2rfc --html -o $@ $?

%.pdf: %.xml
	xml2rfc --pdf -o $@ $?
