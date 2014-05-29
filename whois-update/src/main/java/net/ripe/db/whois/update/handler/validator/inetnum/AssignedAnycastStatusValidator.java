package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.domain.attrs.Inet6numStatus;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.domain.attrs.OrgType;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import net.ripe.db.whois.update.rest.SubAllocationWindowRESTCaller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

@Component
public class AssignedAnycastStatusValidator implements BusinessRuleValidator {
    public static final int REQUIRED_PREFIX_LENGTH = 24;

    private final RpslObjectUpdateDao rpslObjectUpdateDao;
    private final RpslObjectDao rpslObjectDao;
    private final Ipv4Tree ipv4Tree;
    private final Maintainers maintainers;

    @Autowired
    public AssignedAnycastStatusValidator(final RpslObjectUpdateDao rpslObjectUpdateDao, final RpslObjectDao rpslObjectDao, final Ipv4Tree ipv4Tree, final Maintainers maintainers) {
        this.rpslObjectUpdateDao = rpslObjectUpdateDao;
        this.rpslObjectDao = rpslObjectDao;
        this.ipv4Tree = ipv4Tree;
        this.maintainers = maintainers;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.INETNUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject updatedObject = update.getUpdatedObject();

        final CIString statusValue = updatedObject.getValueForAttribute(AttributeType.STATUS);
        if (InetnumStatus.ASSIGNED_ANYCAST.equals(InetStatusHelper.getStatus(statusValue, updatedObject))) {
            checkRequiredPrefixLength(update, updateContext, updatedObject);
        }
    }

    private void checkRequiredPrefixLength(final PreparedUpdate update, final UpdateContext updateContext, RpslObject updatedObject) {
        final Ipv4Resource ipv4Resource = Ipv4Resource.parse(updatedObject.getKey());
        int inetPrefixLength = ipv4Resource.getPrefixLength();

        if (inetPrefixLength == REQUIRED_PREFIX_LENGTH) {
            checkNoChildren(update, updateContext, updatedObject, ipv4Resource);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastPrefixLengthMustBe(REQUIRED_PREFIX_LENGTH, inetPrefixLength));
        }
    }

    private void checkNoChildren(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        List<Ipv4Entry> children = ipv4Tree.findAllMoreSpecific(ipv4Resource);

        if (children.isEmpty()) {
            checkOrganisationAndDecideIfEndUserOrLIR(update, updateContext, updatedObject, ipv4Resource);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastCannotHaveChildren(children.get(0).getKey().toString()));
        }
    }

    private void checkOrganisationAndDecideIfEndUserOrLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        RpslObject referencedOrganisation = findOrgReference(update);

        if (referencedOrganisation != null) {
            CIString orgTypeStr = referencedOrganisation.findAttribute(AttributeType.ORG_TYPE).getCleanValue();
            OrgType orgType = OrgType.getFor(orgTypeStr);

            if (OrgType.EU_PI.equals(orgType)) {
                continueCheckingForEndUser(update, updateContext, updatedObject, ipv4Resource);
            } else {
                continueCheckingForLIR(update, updateContext, updatedObject, ipv4Resource);
            }
        } else {
            continueCheckingForLIR(update, updateContext, updatedObject, ipv4Resource);
        }
    }

    private RpslObject findOrgReference(final RpslObject object) {
        RpslObject orgReference = null;
        final List<RpslAttribute> updatedOrgAttributes = object.findAttributes(AttributeType.ORG);
        if (!updatedOrgAttributes.isEmpty()) {
            final RpslAttribute org = updatedOrgAttributes.get(0);
            if (org != null) {
                final RpslObjectInfo referencedOrganisationInfo = rpslObjectUpdateDao.getAttributeReference(org.getType(), org.getCleanValue());
                if (referencedOrganisationInfo != null) {
                    orgReference = rpslObjectDao.getByKey(ObjectType.ORGANISATION, referencedOrganisationInfo.getKey());
                }
            }
        }
        return orgReference;
    }

    private RpslObject findOrgReference(final PreparedUpdate update) {
        return findOrgReference(update.getUpdatedObject());
    }

    private void continueCheckingForEndUser(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        checkNoParentOrParentOfCorrectTypeForEndUser(update, updateContext, updatedObject, ipv4Resource);
    }

    private void checkNoParentOrParentOfCorrectTypeForEndUser(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        Ipv4Entry parentEntry = ipv4Tree.findFirstLessSpecific(ipv4Resource).get(0);

        if (parentEntry != null) {
            RpslObject parentObject = rpslObjectDao.getById(parentEntry.getObjectId());
            InetStatus parentStatus = InetStatusHelper.getStatus(parentObject);

            if (parentStatus == null || !InetnumStatus.ALLOCATED_UNSPECIFIED.equals(parentStatus)) {
                updateContext.addMessage(update, UpdateMessages.assignedAnycastEUInvalidParentStatus());
                return;
            }
        }

        checkMaintainerForEndUser(update, updateContext, updatedObject);
    }

    private void checkMaintainerForEndUser(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject) {
        Set<CIString> mntByValues = updatedObject.getValuesForAttribute(AttributeType.MNT_BY);
        Set<CIString> powerMaintainers = maintainers.getPowerMaintainers();

        if (Sets.intersection(mntByValues, powerMaintainers).isEmpty()) {
            String firstPowerMaintainer = powerMaintainers.iterator().next().toString();
            updateContext.addMessage(update, UpdateMessages.assignedAnycastEUInvalidMntByStatus(firstPowerMaintainer));
        }
    }

    private void continueCheckingForLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        checkHasParentForLIR(update, updateContext, updatedObject, ipv4Resource);
    }

    private void checkHasParentForLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Resource ipv4Resource) {
        Ipv4Entry parentEntry = ipv4Tree.findFirstLessSpecific(ipv4Resource).get(0);
        if (parentEntry != null) {
            checkParentOfCorrectTypeForLIR(update, updateContext, updatedObject, parentEntry);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastLIRMustHaveParent());
        }
    }

    private void checkParentOfCorrectTypeForLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, Ipv4Entry parentEntry) {
        RpslObject parentObject = rpslObjectDao.getById(parentEntry.getObjectId());
        InetStatus parentStatus = InetStatusHelper.getStatus(parentObject);

        if (InetnumStatus.ALLOCATED_PA.equals(parentStatus)) {
            checkParentHasOrg(update, updateContext, updatedObject, parentObject);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastLIRParentMustBeOfStatus(InetnumStatus.ALLOCATED_PA.toString()));
        }
    }

    private void checkParentHasOrg(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, RpslObject parentObject) {
        RpslObject referencedOrganisationForParent = findOrgReference(parentObject);

        if (referencedOrganisationForParent != null) {
            checkParentOrgIsLIR(update, updateContext, updatedObject, parentObject, referencedOrganisationForParent);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastLIRParentMustHaveAReferencedOrg());
        }
    }

    private void checkParentOrgIsLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, RpslObject parentObject, RpslObject referencedOrganisationForParent) {

        CIString orgTypeStr = referencedOrganisationForParent.findAttribute(AttributeType.ORG_TYPE).getCleanValue();
        OrgType orgType = OrgType.getFor(orgTypeStr);

        if (OrgType.LIR.equals(orgType)) {
            checkHasMaintainerForLIR(update, updateContext, updatedObject, parentObject);
        } else {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastLIRParentMustHaveAReferencedOrgOfTypeLIR());
        }
    }

    private void checkHasMaintainerForLIR(PreparedUpdate update, UpdateContext updateContext, RpslObject updatedObject, RpslObject parentObject) {
        Set<CIString> mntByValues = updatedObject.getValuesForAttribute(AttributeType.MNT_BY);
        Set<CIString> mntLowerValues = updatedObject.getValuesForAttribute(AttributeType.MNT_LOWER);
        Set<CIString> mntLowerParent = parentObject.getValuesForAttribute(AttributeType.MNT_LOWER);

        if (Sets.intersection(mntByValues, mntLowerParent).isEmpty() || Sets.intersection(mntLowerValues, mntLowerParent).isEmpty()) {
            updateContext.addMessage(update, UpdateMessages.assignedAnycastLIRMaintainerMustBeLIRsMntLower());
        }
    }
}