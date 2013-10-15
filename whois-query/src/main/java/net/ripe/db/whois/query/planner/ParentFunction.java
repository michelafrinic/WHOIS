package net.ripe.db.whois.query.planner;

/*-AFRINIC-*/

import com.google.common.base.Function;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv6Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
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

    private final Ipv4Tree ipv4Tree;
    private final Ipv6Tree ipv6Tree;

    public ParentFunction(
            Ipv4Tree ipv4Tree,
            Ipv6Tree ipv6Tree) {
        this.ipv4Tree = ipv4Tree;
        this.ipv6Tree = ipv6Tree;
    }

    @Nullable
    @Override
    public Iterable<? extends ResponseObject> apply(@Nullable ResponseObject input) {
        if (input instanceof RpslObject) {
            final RpslObject object = (RpslObject) input;
            ObjectType objectType = object.getType();
            if (ObjectType.INETNUM == objectType)  {
                Ipv4Resource ipv4Resource = Ipv4Resource.parse(object.getKey());
                List<Ipv4Entry> ipv4EntryList = ipv4Tree.findFirstLessSpecific(ipv4Resource);
                Ipv4Entry parent = null;
                if (ipv4EntryList != null && !ipv4EntryList.isEmpty()) {
                    parent = ipv4EntryList.get(ipv4EntryList.size()-1);
                }
                if (parent == null) {
                    return Arrays.asList(input, new MessageObject("parent:         0.0.0.0 - 255.255.255.255"));
                } else {
                    return Arrays.asList(input, new MessageObject("parent:         " + parent.getKey().toRangeString()));
                }

            } else if (ObjectType.INET6NUM == objectType) {
                Ipv6Resource ipv6Resource = Ipv6Resource.parse(object.getKey());
                List<Ipv6Entry> ipv6EntryList = ipv6Tree.findFirstLessSpecific(ipv6Resource);
                Ipv6Entry parent = null;
                if (ipv6EntryList != null && !ipv6EntryList.isEmpty()) {
                    parent = ipv6EntryList.get(ipv6EntryList.size()-1);
                }

                if (parent == null) {
                    return Arrays.asList(input, new MessageObject("parent:         ::0 - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
                } else {
                    return Arrays.asList(input, new MessageObject("parent:         " + parent.getKey().toString()));
                }
            }

        }
        return Collections.singletonList(input);
    }
}
