package net.ripe.db.whois.update.handler.validator.autnum;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

@Component
public class AutNumValidator implements BusinessRuleValidator {
    private final Maintainers maintainers;

    @Autowired
    public AutNumValidator(final Maintainers maintainers) {
        this.maintainers = maintainers;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.AUT_NUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject updatedObject = update.getUpdatedObject();

        Set<CIString> mntByValues = updatedObject.getValuesForAttribute(AttributeType.MNT_BY);
        Set<CIString> powerMaintainers = maintainers.getPowerMaintainers();

        if (Sets.intersection(mntByValues, powerMaintainers).isEmpty()) {
            String firstPowerMaintainer = powerMaintainers.iterator().next().toString();
            updateContext.addMessage(update, UpdateMessages.invalidMntByStatus(firstPowerMaintainer));
        }
    }
}