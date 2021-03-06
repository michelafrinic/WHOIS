package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.attrs.Inet6numStatus;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.iptree.Ipv6Entry;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
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
public class AssignedPAStatusValidator implements BusinessRuleValidator {
    private static final int MAX_ALLOWED_ASSIGNED_PA = 2;
    private static final int MAX_ASSIGNMENT_SIZE = 128;

    private final Ipv6Tree ipv6Tree;
    private final RpslObjectDao rpslObjectDao;

    @Autowired
    public AssignedPAStatusValidator(final Ipv6Tree ipv6Tree, final RpslObjectDao rpslObjectDao) {
        this.ipv6Tree = ipv6Tree;
        this.rpslObjectDao = rpslObjectDao;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.INET6NUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        if (update.getAction().equals(Action.CREATE)) {
            validateCreate(update, updateContext);
        }
    }

    private void validateCreate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject object = update.getUpdatedObject();
        final Ipv6Resource ipv6Resource = Ipv6Resource.parse(object.getKey());

        final Inet6numStatus status = Inet6numStatus.getStatusFor(object.getValueForAttribute(AttributeType.STATUS));
        if (status.equals(Inet6numStatus.ASSIGNED_PA)) {
            validTotalAssignedPAInHierarchy(update, updateContext, ipv6Resource);
        } else {
            for (final RpslAttribute attribute : object.findAttributes(AttributeType.ASSIGNMENT_SIZE)) {
                updateContext.addMessage(update, attribute, UpdateMessages.attributeAssignmentSizeNotAllowed());
            }
        }

        validatePrefixLengthForParent(update, updateContext, ipv6Resource);
    }

    private void validatePrefixLengthForParent(final PreparedUpdate update, final UpdateContext updateContext, final Ipv6Resource ipv6Resource) {
        final List<Ipv6Entry> parents = ipv6Tree.findFirstLessSpecific(ipv6Resource);
        Validate.notEmpty(parents, "Parent must always exist");
        final RpslObject parent = rpslObjectDao.getById(parents.get(0).getObjectId());

        final InetStatus parentStatus = InetStatusHelper.getStatus(parent);
        if (parentStatus == null) {
            updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Parent", parent.getKey(), parent.getValueForAttribute(AttributeType.STATUS)));
            return;
        }

        if (parentStatus.equals(Inet6numStatus.ASSIGNED_PA)) {
            final int parentAssignmentSize = parent.getValueForAttribute(AttributeType.ASSIGNMENT_SIZE).toInt();
            final int prefixLength = ipv6Resource.getPrefixLength();
            if (prefixLength != parentAssignmentSize) {
                updateContext.addMessage(update, UpdateMessages.invalidPrefixLength(ipv6Resource, parentAssignmentSize));
            }
        }
    }

    private void validTotalAssignedPAInHierarchy(final PreparedUpdate update, final UpdateContext updateContext, final Ipv6Resource ipv6Resource) {
        int remaining = MAX_ALLOWED_ASSIGNED_PA - 1;

        for (final Ipv6Entry parentEntry : Lists.reverse(ipv6Tree.findAllLessSpecific(ipv6Resource))) {
            if (isAssignedPA(parentEntry) && remaining-- == 0) {
                updateContext.addMessage(update, UpdateMessages.tooManyAssignedPAInHierarchy());
                return;
            }
        }

        if (!validChildNrAssignedPA(ipv6Resource, remaining)) {
            updateContext.addMessage(update, UpdateMessages.tooManyAssignedPAInHierarchy());
        }
    }

    private boolean validChildNrAssignedPA(final Ipv6Resource ipv6Resource, final int remaining) {
        for (final Ipv6Entry childEntry : ipv6Tree.findFirstMoreSpecific(ipv6Resource)) {
            if (isAssignedPA(childEntry) && (remaining == 0 || !validChildNrAssignedPA(childEntry.getKey(), remaining - 1))) {
                return false;
            }
        }

        return true;
    }

    private boolean isAssignedPA(final Ipv6Entry entry) {
        final RpslObject object = rpslObjectDao.getById(entry.getObjectId());
        final Inet6numStatus status = Inet6numStatus.getStatusFor(object.getValueForAttribute(AttributeType.STATUS));
        return Inet6numStatus.ASSIGNED_PA.equals(status);
    }
}
