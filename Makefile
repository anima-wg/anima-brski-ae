LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif


# extra stuff.
YANGDATE=2021-05-29
VRDATE=yang/ietf-async-voucher-request@${YANGDATE}.yang

ietf-async-voucher-request-tree.txt: ${VRDATE}
	pyang --path=yang -f tree --tree-print-groupings ${VRDATE} > $@

${VRDATE}: ietf-async-voucher-request.yang
	mkdir -p yang
	sed -e"s/YYYY-MM-DD/${YANGDATE}/" ietf-async-voucher-request.yang > ${VRDATE}

${VRDATE}.xml: ${VRDATE}
	(echo '<artwork name="yang-agent-data" type="" align="left" alt=""><![CDATA['; cat ${VRDATE}; echo; echo ']]></artwork>') >${VRDATE}.xml

clean::
	-rm -f ietf-voucher-request@*.yang

.PRECIOUS: ${DRAFT}-${VERSION}.xml
.PRECIOUS: ${VRDATE}
.PRECIOUS: ALL-${DRAFT}.xml
.PRECIOUS: DATE-${DRAFT}.xml

