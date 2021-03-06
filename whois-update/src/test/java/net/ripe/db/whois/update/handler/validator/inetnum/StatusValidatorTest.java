package net.ripe.db.whois.update.handler.validator.inetnum;


import com.google.common.collect.Lists;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Entry;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Principal;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static net.ripe.db.whois.common.domain.CIString.ciSet;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusValidatorTest {
    @Mock PreparedUpdate update;
    @Mock UpdateContext updateContext;
    @Mock RpslObjectDao objectDao;
    @Mock Ipv4Tree ipv4Tree;
    @Mock Ipv6Tree ipv6Tree;
    @Mock Ipv4Entry ipEntry;
    @Mock Subject authenticationSubject;
    @Mock Maintainers maintainers;
    @InjectMocks StatusValidator subject;

    @Before
    public void setup() {
        when(update.getAction()).thenReturn(Action.CREATE);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(updateContext.getSubject(update)).thenReturn(authenticationSubject);

        when(maintainers.getEnduserMaintainers()).thenReturn(ciSet("RIPE-NCC-HM-MNT"));
        when(maintainers.getRsMaintainers()).thenReturn(ciSet("RIPE-NCC-HM-MNT"));
    }

    @Test
    public void child_status_missing_results_in_warning_ipv4() {
        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/16");
        final Ipv4Entry parent = new Ipv4Entry(ipv4Resource, 1);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ALLOCATED PA"));
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);

        final RpslObject child = new RpslObject(2, Lists.newArrayList(new RpslAttribute("inetnum", "192.0/32")));
        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("192.0/32"), 2);
        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(objectDao.getById(child.getObjectId())).thenReturn(child);

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(parent));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.0/16"));


        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.objectLacksStatus("Child", child.getKey()));
    }

    @Test
    public void child_status_missing_results_in_warning_ipv4_override() {
        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/16");
        final Ipv4Entry parent = new Ipv4Entry(ipv4Resource, 1);
        when(update.isOverride()).thenReturn(true);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ALLOCATED PA"));
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);

        final RpslObject child = new RpslObject(2, Lists.newArrayList(new RpslAttribute("inetnum", "192.0/32")));
        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("192.0/32"), 2);
        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(objectDao.getById(child.getObjectId())).thenReturn(child);

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(parent));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.0/16"));


        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void invalid_child_status_fails_ipv4() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);

        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/32");
        final Ipv4Entry child = new Ipv4Entry(ipv4Resource, 1);
        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(child));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ALLOCATED PA"));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.0/32\nstatus: ASSIGNED PI"));


        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.incorrectChildStatus("ALLOCATED PA", "ASSIGNED PI"));
    }

    @Test
    public void invalid_child_status_fails_ipv4_override() {
        when(update.isOverride()).thenReturn(true);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);

        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/32");
        final Ipv4Entry child = new Ipv4Entry(ipv4Resource, 1);
        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(child));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ALLOCATED PA"));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.0/32\nstatus: ALLOCATED PI"));


        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void not_authorized_by_rsmntner_ipv4() {
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 0.0.0.0 - 255.255.255"));
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(false);
        //when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED ANYCAST"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ALLOCATED UNSPECIFIED")); // ALLOCATED UNSPECIFIED requires RsMaintainer

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.statusRequiresAuthorization("ALLOCATED UNSPECIFIED"));
    }

    @Test
    public void not_authorized_by_rsmntner_ipv4_override() {
        when(update.isOverride()).thenReturn(true);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 0.0.0.0 - 255.255.255"));
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(false);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED ANYCAST"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void parent_has_assigned_pa_status_and_grandparent_is_allocated_pa_and_has_rs_maintainer() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.168.1.0/24\nstatus: ASSIGNED PA"));

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.168/16"), 1);
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.168/16\nstatus: ASSIGNED PA"));
        Ipv4Entry grandParentEntry = new Ipv4Entry(Ipv4Resource.parse("192/8"), 2);
        when(objectDao.getById(2)).thenReturn(RpslObject.parse("inetnum: 192/8\nstatus: ALLOCATED PA\nmnt-by: RIPE-NCC-HM-MNT"));
        when(ipv4Tree.findAllLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry, grandParentEntry));
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.incorrectParentStatus(ObjectType.INETNUM, "ASSIGNED PA"));
    }

    @Test
    public void parent_has_assigned_pa_status_and_grandparent_is_allocated_pa_but_does_not_have_rs_maintainer() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.168.1.0/24\nstatus: ASSIGNED PA"));

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.168/16"), 1);
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inetnum: 192.168/16\nstatus: ASSIGNED PA"));
        Ipv4Entry grandParentEntry = new Ipv4Entry(Ipv4Resource.parse("192/8"), 2);
        when(objectDao.getById(2)).thenReturn(RpslObject.parse("inetnum: 192/8\nstatus: ALLOCATED PA"));
        when(ipv4Tree.findAllLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry, grandParentEntry));
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));

        subject.validate(update, updateContext);

        verify(updateContext, never()).addMessage(update, UpdateMessages.incorrectParentStatus(ObjectType.INETNUM, "ASSIGNED PA"));
    }

    @Test
    public void parent_has_no_status_ipv4() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PI"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.0/16"), 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inetnum: 192.0/16");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.objectLacksStatus("Parent", "192.0/16"));
    }

    @Test
    public void parent_has_no_status_ipv4_override() {
        when(update.isOverride()).thenReturn(true);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PI"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.0/16"), 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inetnum: 192.0/16");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void incorrect_parent_status_ipv4() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PI"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.0/16"), 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inetnum: 192.0/16\nstatus: SUB-ALLOCATED PA");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.incorrectParentStatus(ObjectType.INETNUM, "SUB-ALLOCATED PA"));
    }

    @Test
    public void incorrect_parent_status_ipv4_override() {
        when(update.isOverride()).thenReturn(true);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PI"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.0/16"), 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inetnum: 192.0/16\nstatus: SUB-ALLOCATED PA");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void correct_parent_status_ipv4() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(authenticationSubject.hasPrincipal(Principal.RS_MAINTAINER)).thenReturn(true);
        when(maintainers.getRsMaintainers()).thenReturn(CIString.ciSet("RIPE-NCC-HM-MNT"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PI\nmnt-by: RIPE-NCC-HM-MNT"));

        when(ipv4Tree.findFirstMoreSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList());

        Ipv4Entry parentEntry = new Ipv4Entry(Ipv4Resource.parse("192.0/16"), 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inetnum: 192.0/16\nstatus: ALLOCATED UNSPECIFIED");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext, never()).addMessage(eq(update), any(Message.class));
    }

    @Test
    public void child_status_missing_results_in_warning_ipv6() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        //when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ALLOCATED-BY-LIR"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI")); // for Afrinic WHOIS
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(false);

        final RpslObject child = new RpslObject(2, Lists.newArrayList(new RpslAttribute("inet6num", "2001::/128")));
        final Ipv6Entry entry = new Ipv6Entry(Ipv6Resource.parse("2001::/128"), 2);
        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(entry));
        when(objectDao.getById(child.getObjectId())).thenReturn(child);

        final Ipv6Resource ipv6Resource = Ipv6Resource.parse("2001::/64");
        final Ipv6Entry parent = new Ipv6Entry(ipv6Resource, 1);
        when(ipv6Tree.findFirstLessSpecific(Ipv6Resource.parse("2001::/48"))).thenReturn(Lists.newArrayList(parent));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inet6num: 2001::/64"));

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.objectLacksStatus("Child", child.getKey()));
    }

    @Test
    public void child_status_missing_results_in_warning_ipv6_override() {
        when(update.isOverride()).thenReturn(true);
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ALLOCATED-BY-LIR"));
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(false);

        final RpslObject child = new RpslObject(2, Lists.newArrayList(new RpslAttribute("inet6num", "2001::/128")));
        final Ipv6Entry entry = new Ipv6Entry(Ipv6Resource.parse("2001::/128"), 2);
        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(entry));
        when(objectDao.getById(child.getObjectId())).thenReturn(child);

        final Ipv6Resource ipv6Resource = Ipv6Resource.parse("2001::/64");
        final Ipv6Entry parent = new Ipv6Entry(ipv6Resource, 1);
        when(ipv6Tree.findFirstLessSpecific(Ipv6Resource.parse("2001::/48"))).thenReturn(Lists.newArrayList(parent));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inet6num: 2001::/64"));

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void invalid_child_status_fails_ipv6() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);

        final Ipv6Resource ipv6Resource = Ipv6Resource.parse("2001::/128");
        final Ipv6Entry child = new Ipv6Entry(ipv6Resource, 1);
        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(child));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ALLOCATED-BY-RIR"));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inet6num: 2001::/128\nstatus: ALLOCATED PI"));


        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.objectHasInvalidStatus("Child", "2001::/128", "ALLOCATED PI"));
    }

    @Test
    public void not_authorized_by_rsmntner_ipv6() {
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.newArrayList(new Ipv6Entry(Ipv6Resource.parse("::0/0"), 1)));
        when(objectDao.getById(1)).thenReturn(RpslObject.parse("inet6num: ::0/0"));
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(false);
        //when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED ANYCAST"));
        // ASSIGNED PI requires Rs Maintainer in Afrinic WHOIS
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI"));

        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList());

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.statusRequiresAuthorization("ASSIGNED PI"));
    }

    @Test
    public void parent_has_no_status_ipv6() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI\nmnt-by: RIPE-NCC-HM-MNT\n"));

        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList());

        Ipv6Entry parentEntry = new Ipv6Entry(Ipv6Resource.parse("2001::/24"), 1);
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inet6num: 2001::/24");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.objectLacksStatus("Parent", "2001::/24"));
    }

    @Test
    public void incorrect_parent_status_ipv6() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.ALLOC_MAINTAINER)).thenReturn(true);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI\nmnt-by: RIPE-NCC-HM-MNT\n"));

        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList());

        Ipv6Entry parentEntry = new Ipv6Entry(Ipv6Resource.parse("2001::/24"), 1);
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(parentEntry));
        //final RpslObject parent = RpslObject.parse("inet6num: 2001::/24\nstatus: ALLOCATED-BY-LIR");
        final RpslObject parent = RpslObject.parse("inet6num: 2001::/24\nstatus: ASSIGNED PI");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.incorrectParentStatus(ObjectType.INET6NUM, "ASSIGNED PI"));
    }

    @Test
    public void incorrect_parent_status_ipv6_2() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.RS_MAINTAINER)).thenReturn(true);
        when(maintainers.getRsMaintainers()).thenReturn(CIString.ciSet("RIPE-NCC-HM-MNT"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI\nmnt-by: RIPE-NCC-HM-MNT\n"));

        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList());

        Ipv6Entry parentEntry = new Ipv6Entry(Ipv6Resource.parse("2001::/24"), 1);
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inet6num: 2001::/24\nstatus: ALLOCATED-BY-RIR");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.incorrectParentStatus(ObjectType.INET6NUM, "ALLOCATED-BY-RIR"));
    }

    @Test
    public void correct_parent_status_ipv6() {
        when(update.getType()).thenReturn(ObjectType.INET6NUM);
        when(authenticationSubject.hasPrincipal(Principal.RS_MAINTAINER)).thenReturn(true);
        when(maintainers.getRsMaintainers()).thenReturn(CIString.ciSet("RIPE-NCC-HM-MNT"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inet6num: 2001::/48\nstatus: ASSIGNED PI\nmnt-by: RIPE-NCC-HM-MNT\n"));

        when(ipv6Tree.findFirstMoreSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList());

        Ipv6Entry parentEntry = new Ipv6Entry(Ipv6Resource.parse("2001::/24"), 1);
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.<Ipv6Entry>newArrayList(parentEntry));
        final RpslObject parent = RpslObject.parse("inet6num: 2001::/24\nstatus: ALLOCATED UNSPECIFIED");
        when(objectDao.getById(1)).thenReturn(parent);

        subject.validate(update, updateContext);

        verify(updateContext, never()).addMessage(eq(update), any(Message.class));
    }

    @Test
    public void modify_same() {
        when(update.getAction()).thenReturn(Action.MODIFY);

        when(update.getReferenceObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/24\n" +
                "status: EARLY-REGISTRATION"));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/24\n" +
                "status: EARLY-REGISTRATION"));

        subject.validate(update, updateContext);
        verify(updateContext, never()).addMessage(eq(update), any(Message.class));
    }

    @Test
    public void create_with_status_notSet() {
        when(update.getAction()).thenReturn(Action.CREATE);

        when(update.getReferenceObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/24\n" +
                "status: EARLY-REGISTRATION"));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/16\n" +
                "status: NOT-SET"));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.statusRequiresAuthorization("NOT-SET"));
    }


    @Test
    public void modify_status_change() {
        when(update.getAction()).thenReturn(Action.MODIFY);

        when(update.getReferenceObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/24\n" +
                "status: EARLY-REGISTRATION"));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "inetnum: 192.0/24\n" +
                "status: ASSIGNED PA"));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.statusChange());
    }

}
