package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.IpRanges;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.domain.attrs.OrgType;
import net.ripe.db.whois.common.iptree.IpEntry;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Principal;
import net.ripe.db.whois.update.domain.*;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import net.ripe.db.whois.update.rest.SubAllocationWindowRESTCaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

import static net.ripe.db.whois.update.handler.validator.inetnum.InetStatusHelper.getStatus;

@Component
public class SubAllocationWindowValidator implements BusinessRuleValidator {
    private static final int MAX_PREFIX_LENGTH = 24;

    private final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller;
    private final RpslObjectUpdateDao rpslObjectUpdateDao;
    private final RpslObjectDao rpslObjectDao;
    private final Ipv4Tree ipv4Tree;

    @Autowired
    public SubAllocationWindowValidator(final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller, final RpslObjectUpdateDao rpslObjectUpdateDao, final RpslObjectDao rpslObjectDao, final Ipv4Tree ipv4Tree) {
        this.subAllocationWindowRESTCaller = subAllocationWindowRESTCaller;
        this.rpslObjectUpdateDao = rpslObjectUpdateDao;
        this.rpslObjectDao = rpslObjectDao;
        this.ipv4Tree = ipv4Tree;
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
        if (InetnumStatus.SUB_ALLOCATED_PA.equals(InetStatusHelper.getStatus(statusValue, updatedObject))) {
            final Ipv4Resource ipv4Resource = Ipv4Resource.parse(updatedObject.getKey());

            final RpslObject referencedOrganisation = findOrgReference(update);
            if (referencedOrganisation != null) {
                validateWithRightOrganisation(update, updateContext, ipv4Resource, referencedOrganisation);
            } else {
                updateContext.addMessage(update, UpdateMessages.orgAttributeMissing());
            }
        }
    }

    private void validateWithRightOrganisation(final PreparedUpdate update, final UpdateContext updateContext, Ipv4Resource ipv4Resource, RpslObject referencedOrganisation) {
        final CIString orgTypeStr = referencedOrganisation.findAttribute(AttributeType.ORG_TYPE).getCleanValue();
        final OrgType orgType = OrgType.getFor(orgTypeStr);

        if (OrgType.LIR.equals(orgType)) {
            validateWithRightOrganisationType(update, updateContext, ipv4Resource, referencedOrganisation);
        } else {
            updateContext.addMessage(update, UpdateMessages.onlyLIRCanCreateSubAllocations());
        }
    }

    private void validateWithRightOrganisationType(final PreparedUpdate update, final UpdateContext updateContext, Ipv4Resource ipv4Resource, RpslObject referencedOrganisation) {
        String orgHdl = referencedOrganisation.findAttribute(AttributeType.ORGANISATION).getValue().trim();
        Integer subAllocationWindowSizePrefix = subAllocationWindowRESTCaller.getSAW4(orgHdl);

        if (subAllocationWindowSizePrefix != null) {
            validateWithRightSubAllocationSizePrefix(update, updateContext, ipv4Resource, subAllocationWindowSizePrefix);
        } else {
            updateContext.addMessage(update, UpdateMessages.noSubAllocationSpecified());
        }
    }

    private void validateWithRightSubAllocationSizePrefix(final PreparedUpdate update, final UpdateContext updateContext, Ipv4Resource ipv4Resource, Integer subAllocationWindowSizePrefix) {
        int inetPrefixLength = ipv4Resource.getPrefixLength();
        final Ipv4Entry parent = ipv4Tree.findFirstLessSpecific(ipv4Resource).get(0);
        int parentInetPrefixLength = parent != null ? parent.getKey().getPrefixLength() : 1;

        if (inetPrefixLength <= MAX_PREFIX_LENGTH && inetPrefixLength > parentInetPrefixLength) {
            validateWithRightPrefixLengths(update, updateContext, inetPrefixLength, subAllocationWindowSizePrefix);
        } else {
            updateContext.addMessage(update, UpdateMessages.invalidPrefixLengthRange(inetPrefixLength, MAX_PREFIX_LENGTH, parentInetPrefixLength));
        }
    }

    private void validateWithRightPrefixLengths(final PreparedUpdate update, final UpdateContext updateContext, int inetPrefixLength, Integer subAllocationWindowSizePrefix) {
        if (subAllocationWindowSizePrefix.intValue() == 0) {
            validateWithSAWIsZero(update, updateContext);
        } else if (subAllocationWindowSizePrefix.intValue() > 0) {
            validateWithSAWIsGreaterThanZero(update, updateContext, inetPrefixLength, subAllocationWindowSizePrefix);
        } else {
            updateContext.addMessage(update, UpdateMessages.subAllocationNotAllowed());
        }
    }

    private void validateWithSAWIsZero(final PreparedUpdate update, final UpdateContext updateContext) {
        boolean hostmaster = updateContext.getSubject(update).isHostmaster();
        if (!hostmaster) {
            updateContext.addMessage(update, UpdateMessages.onlyHostMasterCanCreateSubAllocationWhenSAWNull());
        }
    }

    private void validateWithSAWIsGreaterThanZero(final PreparedUpdate update, final UpdateContext updateContext, int inetPrefixLength, int subAllocationWindowSizePrefix) {
        if (inetPrefixLength < subAllocationWindowSizePrefix) {
            updateContext.addMessage(update, UpdateMessages.rangeTooHighForStatusSAW(subAllocationWindowSizePrefix, inetPrefixLength));
        }
    }

    private RpslObject findOrgReference(final PreparedUpdate update) {
        RpslObject orgReference = null;
        final List<RpslAttribute> updatedOrgAttributes = update.getUpdatedObject().findAttributes(AttributeType.ORG);
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
}