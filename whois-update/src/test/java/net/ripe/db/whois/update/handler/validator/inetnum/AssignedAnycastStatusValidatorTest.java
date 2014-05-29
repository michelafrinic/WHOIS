package net.ripe.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.*;
import net.ripe.db.whois.update.rest.SubAllocationWindowRESTCaller;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class AssignedAnycastStatusValidatorTest {
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;
    @Mock
    RpslObjectUpdateDao rpslObjectUpdateDao;
    @Mock
    RpslObjectDao rpslObjectDao;
    @Mock
    Ipv4Tree ipv4Tree;
    @InjectMocks
    AssignedAnycastStatusValidator subject;

    @Test
    public void getActions() {
        assertThat(subject.getActions(), contains(Action.CREATE));
    }

    @Test
    public void getTypes() {
        assertThat(subject.getTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void validate_OtherThanAssignedAnycast() {
        InetnumStatus[] inetnumStatuses = InetnumStatus.values();

        for (int i = 0; i < inetnumStatuses.length; i++) {
            InetnumStatus status = inetnumStatuses[i];

            if (!status.equals(InetnumStatus.ASSIGNED_ANYCAST)) {
                when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                        "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                        "netname:        AFRINIC\n" +
                        "status:         " + status.toString() + "\n"));

                subject.validate(update, updateContext);
                verifyZeroInteractions(updateContext);
            }
        }
    }

    @Test
    public void checkWrongPrefixLength1() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.128/26\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST");

        when(update.getUpdatedObject()).thenReturn(inetnum);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastPrefixLengthMustBe(AssignedAnycastStatusValidator.REQUIRED_PREFIX_LENGTH, 26));
    }

    @Test
    public void checkWrongPrefixLength2() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.206.0/23\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST");

        when(update.getUpdatedObject()).thenReturn(inetnum);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastPrefixLengthMustBe(AssignedAnycastStatusValidator.REQUIRED_PREFIX_LENGTH, 23));
    }

    @Test
    public void checkInetnumWithChildrenFails() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.0/24\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST");

        Ipv4Entry ipv4Entry = new Ipv4Entry(Ipv4Resource.parse("102.100.255.1/32"), 1);
        List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();
        children.add(ipv4Entry);

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastCannotHaveChildren("102.100.255.1/32"));
    }
}
