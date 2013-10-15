package net.ripe.db.whois.query.planner;

/*-AFRINIC-*/

import com.google.common.base.Function;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.query.domain.MessageObject;
import net.ripe.db.whois.query.domain.QueryMessages;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: yogesh
 * Date: 10/14/13
 * Time: 11:48 AM
 */
public class ParentFunction implements Function<ResponseObject, Iterable<? extends ResponseObject>> {

    private static final Set<ObjectType> OBJECT_TYPES = Sets.newHashSet(ObjectType.INETNUM, ObjectType.INET6NUM);

    private final SourceContext sourceContext;
    private final AuthoritativeResourceData authoritativeResourceData;

    public ParentFunction(SourceContext sourceContext, AuthoritativeResourceData authoritativeResourceData) {
        this.sourceContext = sourceContext;
        this.authoritativeResourceData = authoritativeResourceData;
        authoritativeResourceData.refreshAuthoritativeResourceCache();
    }

    @Nullable
    @Override
    public Iterable<? extends ResponseObject> apply(@Nullable ResponseObject input) {
        if (input instanceof RpslObject) {
            final RpslObject object = (RpslObject) input;

            if (OBJECT_TYPES.contains(object.getType())) {
                final AuthoritativeResource resourceData = authoritativeResourceData.getAuthoritativeResource(sourceContext.getCurrentSource().getName());

                Ipv4Resource ipv4Resource = Ipv4Resource.parse(object.getKey());
                Ipv4Resource parent = resourceData.getParent(ipv4Resource);

                if (parent != null) {
                    return Arrays.asList(input, new MessageObject("parent:        " + parent.toRangeString()));
                }
            }
        }
        return Collections.singletonList(input);
    }
}
