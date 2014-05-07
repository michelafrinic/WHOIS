package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.iptree.IpEntry;
import net.ripe.db.whois.common.iptree.IpTree;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.apache.commons.lang.Validate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class NoReverseUnlessAssignedValidator implements BusinessRuleValidator {
    private final Ipv4Tree ipv4Tree;
    private final Ipv6Tree ipv6Tree;
    private final RpslObjectDao objectDao;

    @Autowired
    public NoReverseUnlessAssignedValidator(final Ipv4Tree ipv4Tree, final Ipv6Tree ipv6Tree, final RpslObjectDao objectDao) {
        this.ipv4Tree = ipv4Tree;
        this.ipv6Tree = ipv6Tree;
        this.objectDao = objectDao;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.INETNUM, ObjectType.INET6NUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        final Domain domain = Domain.parse(update.getUpdatedObject().getKey());
        if (domain.getType() == Domain.Type.E164) {
            return;
        }

        final IpInterval reverseIp = domain.getReverseIp();

        if (domain.getType() == Domain.Type.INADDR) {
            validateMoreSpecificFound(update, updateContext, reverseIp, ipv4Tree);
        } else {
            validateMoreSpecificFound(update, updateContext, reverseIp, ipv6Tree);
        }
    }

    private void validateMoreSpecificFound(final PreparedUpdate update, final UpdateContext updateContext, final IpInterval reverseIp, final IpTree ipTree) {
        final List<IpEntry> parentInetnum = ipTree.findFirstLessSpecific(reverseIp);
        Validate.notEmpty(parentInetnum, "Should always have a parent");

        List<RpslObjectInfo> rpslObjectInfoList = objectDao.findByAttribute(AttributeType.ADDRESS, parentInetnum.get(0).toString());
        RpslObjectInfo reverseIpInfo = rpslObjectInfoList.get(0);
        RpslObject reverseObject = objectDao.getById(reverseIpInfo.getObjectId());

        final InetnumStatus objectStatus = InetnumStatus.getStatusFor(reverseObject.getValueForAttribute(AttributeType.STATUS));

        if (objectStatus.equals(InetnumStatus.ALLOCATED_PA)) {
            final List<IpEntry> childEntries = ipTree.findFirstMoreSpecific(reverseIp);
            if (childEntries.isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.noMoreSpecificInetnumFound(reverseObject.toString()));
            }
        }

        if (objectStatus.equals(InetnumStatus.ASSIGNED_PI) || objectStatus.equals(InetnumStatus.ASSIGNED_PA) || objectStatus.equals(InetnumStatus.SUB_ALLOCATED_PA)) {
            return;
        }

        /*Interval firstIntersecting = null;
        final List<IpEntry> childEntries = ipTree.findFirstMoreSpecific((IpInterval) parent.get(0).getKey());
        for (final IpEntry childEntry : childEntries) {
            final Interval child = childEntry.getKey();

            if (child.intersects(ipInterval) && !(child.contains(ipInterval) || ipInterval.contains(child))) {
                if (firstIntersecting == null || firstIntersecting.singletonIntervalAtLowerBound().compareUpperBound(child.singletonIntervalAtLowerBound()) > 0) {
                    firstIntersecting = child;
                }
            }
        }

        if (firstIntersecting != null) {
            updateContext.addMessage(update, UpdateMessages.intersectingRange(firstIntersecting));
        }*/
    }
}
