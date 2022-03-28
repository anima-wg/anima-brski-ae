DRAFT:=draft-ietf-anima-brski-ae

html: xml
	xml2rfc ${DRAFT}.xml --html

xml:
	kdrfc ${DRAFT}.md
