# installation hints for needed software components:
#
# for Linux:
# pip install xml2rfc
# sudo gem install kramdown-rfc2629
# sudo apt install weasyprint # for PDF output
# npm install -g aasv         # for aasvg support
# sudo apt install python3-venv
# sudo gem install enscript
#
# for MacOS:
# brew install node
# npm install -g aasvg
# pip install xml2rfc
# sudo gem install kramdown-rfc
# pip install 'weasyprint>=53.0,!=57.0,!=60.0'  # for PDF output

SHELL=bash # This is for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-ae
VERSION:=$(shell sed -n -e'/docname/s,.*[^0-9]*-\([0-9]*\).*,\1,p' $* ${DRAFT}.md)
LATEST_TXT=${DRAFT}-${VERSION}.txt

.phony: default all update generate version diff log commit clean

default: ${LATEST_TXT}

all: ${DRAFT}.txt ${DRAFT}.html ${DRAFT}.pdf

.PRECIOUS: ${DRAFT}.{xml,txt,html,pdf}

update: clean
	git fetch origin
	git rebase origin || \
	  (git checkout --theirs origin/master -- ${DRAFT}.{xml,txt,html} && \
	   git rebase --continue)

generate:
	kdrfc --v3 -t -h ${PDF} ${DRAFT}.md

# produces also .xml and .html:
%.txt: %.md
	$(MAKE) generate PDF=-P

# not needed:
%.xml: %.md
	kdrfc --v3 -x $?

# not needed:
%.txt: %.xml
	xml2rfc --text -o $@ $?

# not needed:
%.html: %.xml
	xml2rfc --html -o $@ $?

# not needed:
%.pdf: %.xml
	xml2rfc --pdf -o $@ $?

${DRAFT}-${VERSION}.txt: ${DRAFT}.txt
	@cp -a ${DRAFT}.txt ${LATEST_TXT}

version:
	@echo Version: ${VERSION}

diff:
	git diff ${DRAFT}.md

log:
	git log -p ${DRAFT}.md

commit: generate
	git add ${LATEST_TXT}
	git commit ${DRAFT}{.{xml,txt,html,pdf},-${VERSION}.txt} \
	   -m "CI - ietf-draft-files (xml, txt, html, pdf) updated" \
	   || echo "No changes to commit"
	 # git push origin

clean:
	git checkout -- ${DRAFT}.{xml,txt,html,pdf}
	git checkout 2>/dev/null -- ${LATEST_TXT} || rm 2>/dev/null -f ${LATEST_TXT}
