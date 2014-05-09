package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
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

@Component
public class SubAllocationWindowValidator implements BusinessRuleValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(SubAllocationWindowValidator.class);
    private String sawUrl = null;

    private final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller;

    @Autowired
    public SubAllocationWindowValidator(final SubAllocationWindowRESTCaller subAllocationWindowRESTCaller) {
        this.subAllocationWindowRESTCaller = subAllocationWindowRESTCaller;
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
        if (sawUrl != null && !"".equals(sawUrl)) {
            final RpslObject updatedObject = update.getUpdatedObject();

            final CIString statusValue = updatedObject.getValueForAttribute(AttributeType.STATUS);
            if (InetnumStatus.SUB_ALLOCATED_PA.equals(InetStatusHelper.getStatus(statusValue, updatedObject))) {
                final Ipv4Resource ipv4Resource = Ipv4Resource.parse(updatedObject.getKey());
                //if (ipv4Resource.getPrefixLength() > SUB_ALLOCATED_PA_MAX_PREFIX) {
                //    updateContext.addMessage(update, UpdateMessages.rangeTooSmallForStatus(InetnumStatus.SUB_ALLOCATED_PA, 24));
                //}
            }
        }
    }
}
