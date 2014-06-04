package net.ripe.db.whois.update.handler.validator.autnum;

import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
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
import net.ripe.db.whois.update.handler.validator.inetnum.AssignedAnycastStatusValidator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class AutNumValidatorTest {
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;
    @Mock
    Maintainers maintainers;
    @InjectMocks
    AutNumValidator subject;

    @Test
    public void getActions() {
        assertThat(subject.getActions(), contains(Action.CREATE,Action.MODIFY));
    }

    @Test
    public void getTypes() {
        assertThat(subject.getTypes(), contains(ObjectType.AUT_NUM));
    }

    @Test
    public void checkAutNumWithoutPowerMaintainerFails() {

        RpslObject autnum = RpslObject.parse("" +
                "aut-num:        AS1234\n" +
                "as-name:        ABCD-AS\n" +
                "org:            ORG-ABCD-AFRINIC\n" +
                "admin-c:        ABC12\n" +
                "tech-c:         ABC12\n" +
                "mnt-by:         JOHN-DOE\n" +
                "changed:        hostmaster@afrinic.net 20140604");

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(autnum);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.invalidMntByStatus("AFRINIC-HM-MNT"));
    }

    @Test
    public void checkAutNumWithPowerMaintainerSucceeds() {

        RpslObject autnum = RpslObject.parse("" +
                "aut-num:        AS1234\n" +
                "as-name:        ABCD-AS\n" +
                "org:            ORG-ABCD-AFRINIC\n" +
                "admin-c:        ABC12\n" +
                "tech-c:         ABC12\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "changed:        hostmaster@afrinic.net 20140604");

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(autnum);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }
}
