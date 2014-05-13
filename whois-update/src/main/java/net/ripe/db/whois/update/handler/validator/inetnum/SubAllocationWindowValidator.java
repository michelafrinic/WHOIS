package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.domain.attrs.OrgType;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
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
    private static final Logger LOGGER = LoggerFactory.getLogger(SubAllocationWindowValidator.class);

    private final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller;
    private final RpslObjectUpdateDao rpslObjectUpdateDao;
    private final RpslObjectDao rpslObjectDao;

    @Autowired
    public SubAllocationWindowValidator(final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller, final RpslObjectUpdateDao rpslObjectUpdateDao, final RpslObjectDao rpslObjectDao) {
        this.subAllocationWindowRESTCaller = subAllocationWindowRESTCaller;
        this.rpslObjectUpdateDao = rpslObjectUpdateDao;
        this.rpslObjectDao = rpslObjectDao;
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
                final CIString orgTypeStr = referencedOrganisation.findAttribute(AttributeType.ORG_TYPE).getCleanValue();
                final OrgType orgType = OrgType.getFor(orgTypeStr);

                if (OrgType.LIR.equals(orgType)) {
                    String orgHdl = referencedOrganisation.findAttribute(AttributeType.ORGANISATION).getValue();
                    Integer subAllocationWindowSizePrefix = subAllocationWindowRESTCaller.getSAW4(orgHdl);

                    if (subAllocationWindowSizePrefix != null) {
                        if (subAllocationWindowSizePrefix.intValue() > 0) {
                            int inetPrefixLength = ipv4Resource.getPrefixLength();
                            if (inetPrefixLength < subAllocationWindowSizePrefix) {
                                updateContext.addMessage(update, UpdateMessages.rangeTooHighForStatusSAW(subAllocationWindowSizePrefix, inetPrefixLength));
                            }
                        } else {
                            updateContext.addMessage(update, UpdateMessages.subAllocationNotAllowed());
                        }
                    } else {
                        updateContext.addMessage(update, UpdateMessages.noSubAllocationSpecified());
                    }
                } else {
                    updateContext.addMessage(update, UpdateMessages.onlyLIRCanCreateSubAllocations());
                }
            } else {
                updateContext.addMessage(update, UpdateMessages.orgAttributeMissing());
            }
        }
    }

    private RpslObject findOrgReference(final PreparedUpdate update) {
        RpslObject orgReference = null;
        final List<RpslAttribute> updatedOrgAttributes = update.getUpdatedObject().findAttributes(AttributeType.ORG);
        if(!updatedOrgAttributes.isEmpty()) {
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