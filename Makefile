# software needed (on Linux):
# pip install xml2rfc
# sudo gem install kramdown-rfc2629
# sudo apt install weasyprint # for PDF output
# npm install -g aasv         # for aasvg support
# sudo apt install python3-venv
# sudo gem install enscript

SHELL=bash # This is for supporting extended file name globbing

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

clean:
	git checkout -- ${DRAFT}.{xml,txt,html,pdf}
