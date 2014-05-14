package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.domain.attrs.Inet6numStatus;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.iptree.*;
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

import java.util.ArrayList;
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
        return Lists.newArrayList(ObjectType.DOMAIN);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {

        final Domain domain = Domain.parse(update.getUpdatedObject().getKey());

        if (domain.getType() == Domain.Type.E164) {
            updateContext.addMessage(update, UpdateMessages.invalidDomainObjectType(domain.getReverseIp().toString()));
            return;
        }

        final IpEntry coveringInetnum = getExactOrFirstLessSpecificInetnum(domain);

        final InetStatus coveringInetStatus = getInetStatusFromIpEntry(coveringInetnum, domain);

        if (coveringInetStatus != null &&
                (coveringInetStatus.equals(InetnumStatus.ASSIGNED_PI)
                || coveringInetStatus.equals(InetnumStatus.ASSIGNED_PA)
                || coveringInetStatus.equals(InetnumStatus.SUB_ALLOCATED_PA)
                || coveringInetStatus.equals(Inet6numStatus.ASSIGNED_PA))) {
            return;
        }

        if (coveringInetStatus != null &&
                (coveringInetStatus.equals(InetnumStatus.ALLOCATED_PA)
                        || coveringInetStatus.equals(Inet6numStatus.ALLOCATED_BY_RIR))) {
            final List<IpEntry> childEntries = getFirstMoreSpecificInetnum(coveringInetnum, domain);

            if (childEntries.isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.noMoreSpecificInetnumFound(domain.getReverseIp().toString()));
            }

        }
    }

    private InetStatus getInetStatusFromIpEntry(final IpEntry ipEntry, final Domain domain) {

        final List<RpslObjectInfo> rpslObjectInfoList =
                objectDao.findByAttribute(AttributeType.ADDRESS, ipEntry.getKey().toString());

        RpslObject rpslObject = null;

        if (!rpslObjectInfoList.isEmpty()) {
            rpslObject = objectDao.getById(rpslObjectInfoList.get(0).getObjectId());
        }

        if (rpslObject == null || domain == null) {
            return null;
        }

        if (domain.getType() == Domain.Type.INADDR) {
            return InetnumStatus.getStatusFor(rpslObject.getValueForAttribute(AttributeType.STATUS));
        }
        else {
            return Inet6numStatus.getStatusFor(rpslObject.getValueForAttribute(AttributeType.STATUS));
        }
    }


    private IpEntry getExactOrFirstLessSpecificInetnum(final Domain domain) {
        List<IpEntry> parentEntries = new ArrayList<>();

        if (domain.getType() == Domain.Type.INADDR) {
            parentEntries.addAll(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse(domain.getReverseIp().toString())));
        }
        else {
            parentEntries.addAll(ipv6Tree.findExactOrFirstLessSpecific(Ipv6Resource.parse(domain.getReverseIp().toString())));
        }

        if (!parentEntries.isEmpty()) {
            return parentEntries.get(0);
        }
        return null;

    }

    private List<IpEntry> getFirstMoreSpecificInetnum(final IpEntry ipEntry, final Domain domain) {

        List<IpEntry> childEntries = new ArrayList<>();

        if (domain.getType() == Domain.Type.INADDR) {
            childEntries.addAll(ipv4Tree.findFirstMoreSpecific(Ipv4Resource.parse(ipEntry.getKey().toString())));
        }
        else {
            childEntries.addAll(ipv6Tree.findFirstMoreSpecific(Ipv6Resource.parse(ipEntry.getKey().toString())));
        }

        return childEntries;

    }

}
