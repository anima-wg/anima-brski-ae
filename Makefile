DRAFT:=draft-ietf-anima-brski-async-enroll

html: xml
	xml2rfc ${DRAFT}.xml --html

xml:
	kdrfc ${DRAFT}.md