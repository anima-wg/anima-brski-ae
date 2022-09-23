# software needed (on Linux):
# pip install xml2rfc
# sudo gem install kramdown-rfc2629
# sudo apt install weasyprint # for PDF output
# npm install -g aasv         # for aasvg support
# sudo apt install python3-venv
# sudo gem install enscript

SHELL=bash # This is for supporting extended file name globbing

DRAFT:=draft-ietf-anima-brski-ae
VERSION:=$(shell ./getver ${DRAFT}.md )

.phony: default update generate version diff log commit

default: ${DRAFT}-${VERSION}.txt

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
	@cp -a ${DRAFT}.txt ${DRAFT}-${VERSION}.txt

version:
	@echo Version: ${VERSION}

diff:
	git diff ${DRAFT}.md

log:
	git log -p ${DRAFT}.md

commit: generate
	# not including PDF because CI cannot find/install weasyprint
	git commit ${DRAFT}.{xml,txt,html} \
	   -m "CI - ietf-draft-files (xml, txt, html) updated" \
	   || echo "No changes to commit"
	git push origin

FILES=${DRAFT}{.{md,xml,txt,html,pdf},-${VERSION}.txt}
upload: default
	cp -a  ${FILES} /tmp
	git checkout -- ${FILES}
	git checkout main
	cp -a /tmp/${FILES} .
	git add ${DRAFT}-${VERSION}.txt
	git commit -m "${DRAFT}-${VERSION}" ${FILES}
	git push
	git checkout master

clean:
	git checkout -- ${DRAFT}.{xml,txt,html,pdf}
