package net.ripe.db.whois.query.planner;

/*-AFRINIC-*/

import com.google.common.base.Function;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.query.domain.MessageObject;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: yogesh
 * Date: 10/14/13
 * Time: 11:48 AM
 */
public class ParentFunction implements Function<ResponseObject, Iterable<? extends ResponseObject>> {

    private final SourceContext sourceContext;
    private final AuthoritativeResourceData authoritativeResourceData;
    private final Ipv4Tree ipv4Tree;

    public ParentFunction(
            SourceContext sourceContext,
            Ipv4Tree ipv4Tree,
            AuthoritativeResourceData authoritativeResourceData) {
        this.sourceContext = sourceContext;
        this.ipv4Tree = ipv4Tree;
        this.authoritativeResourceData = authoritativeResourceData;
        authoritativeResourceData.refreshAuthoritativeResourceCache();
    }

    @Nullable
    @Override
    public Iterable<? extends ResponseObject> apply(@Nullable ResponseObject input) {
        if (input instanceof RpslObject) {
            final RpslObject object = (RpslObject) input;
            final AuthoritativeResource resourceData = authoritativeResourceData.getAuthoritativeResource(sourceContext.getCurrentSource().getName());
            ObjectType objectType = object.getType();
            if (ObjectType.INETNUM == objectType)  {

                Ipv4Resource ipv4Resource = Ipv4Resource.parse(object.getKey());

                /*
                Ipv4Resource parent = resourceData.getParent(ipv4Resource);
                if (parent == null) {
                    return Arrays.asList(input, new MessageObject("parent:         0.0.0.0 - 255.255.255.255"));
                } else {
                    return Arrays.asList(input, new MessageObject("parent:         " + parent.toRangeString()));
                } */

                List<Ipv4Entry> ipv4EntryList = ipv4Tree.findFirstLessSpecific(ipv4Resource);
                Ipv4Entry parent2 = null;
                if (ipv4EntryList != null && !ipv4EntryList.isEmpty()) {
                    parent2 = ipv4EntryList.get(ipv4EntryList.size()-1);
                }
                if (parent2 == null) {
                    return Arrays.asList(input, new MessageObject("parent:         0.0.0.0 - 255.255.255.255"));
                } else {
                    return Arrays.asList(input, new MessageObject("parent:         " + parent2.toString()));
                }

            } else if (ObjectType.INET6NUM == objectType) {
                Ipv6Resource ipv6Resource = Ipv6Resource.parse(object.getKey());
                Ipv6Resource parent = resourceData.getParent6(ipv6Resource);

                if (parent == null) {
                    return Arrays.asList(input, new MessageObject("parent:         ::0 - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
                } else {
                    return Arrays.asList(input, new MessageObject("parent:         " + parent.toString()));
                }
            }

        }
        return Collections.singletonList(input);
    }
}
