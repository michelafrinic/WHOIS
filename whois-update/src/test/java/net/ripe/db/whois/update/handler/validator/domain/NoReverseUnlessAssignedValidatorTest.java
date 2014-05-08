package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Entry;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NoReverseUnlessAssignedValidatorTest {
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;

    @Mock
    Ipv4Tree ipv4Tree;
    @Mock
    Ipv6Tree ipv6Tree;
    @Mock
    RpslObjectDao objectDao;
    @InjectMocks
    NoReverseUnlessAssignedValidator subject;

    RpslObject parentIpv4;
    Ipv4Resource parentIpv4Key;
    Ipv4Entry parentIpv4Entry;

    RpslObject parentIpv6;
    Ipv6Resource parentIpv6Key;
    Ipv6Entry parentIpv6Entry;

    @Before
    public void setUp() throws Exception {
        parentIpv4 = RpslObject.parse("inetnum: 0/0");
        parentIpv4Key = Ipv4Resource.parse(parentIpv4.getKey());
        parentIpv4Entry = new Ipv4Entry(parentIpv4Key, 1);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(parentIpv4Entry));

        parentIpv6 = RpslObject.parse("inet6num: ::0/0");
        parentIpv6Key = Ipv6Resource.parse(parentIpv6.getKey());
        parentIpv6Entry = new Ipv6Entry(parentIpv6Key, 2);
        when(ipv6Tree.findFirstLessSpecific(any(Ipv6Resource.class))).thenReturn(Lists.newArrayList(parentIpv6Entry));
    }

    @Test
    public void validate_allocated_pa_with_children_slash16domain_slash16inetnum() {

        final RpslObject object = RpslObject.parse("inetnum: 102.2.0.0 - 102.2.255.255" +
                "\nstatus: ALLOCATED PA");

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.0 - 102.2.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.2.0.0 - 102.2.255.255"));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);
        when(objectDao.getById(anyInt())).thenReturn(object);

        when(ipv4Tree.findFirstMoreSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.10 - 102.0.0.12"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.1/24"), 2)
        ));

        subject.validate(update, updateContext);

        verifyNoMoreInteractions(updateContext);
    }

    @Test
    public void validate_allocated_pa_without_children_slash16domain_slash16inetnum() {
        final RpslObject object = RpslObject.parse("inetnum: 102.2.0.0 - 102.2.255.255" +
                "\nstatus: ALLOCATED PA");

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.0 - 102.2.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.2.0.0 - 102.2.255.255"));

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);
        when(objectDao.getById(anyInt())).thenReturn(object);


        when(ipv4Tree.findFirstMoreSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(new ArrayList<Ipv4Entry>());

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.noMoreSpecificInetnumFound(object.toString()));

    }

    @Test
    public void validate_assigned_pi_slash16domain_slash16inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.0 - 102.2.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.2.0.0 - 102.2.255.255"));


        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);


        final RpslObject object = RpslObject.parse("inetnum: 102.2.0.0 - 102.2.255.255" +
                "\nstatus: ASSIGNED PI");
        when(objectDao.getById(anyInt())).thenReturn(object);

        subject.validate(update, updateContext);

        verifyNoMoreInteractions(updateContext);
    }

    @Test
    public void validate_assigned_pa_slash16domain_slash16inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.0 - 102.2.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.2.0.0 - 102.2.255.255"));


        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);


        final RpslObject object = RpslObject.parse("inetnum: 102.2.0.0 - 102.2.255.255" +
                "\nstatus: ASSIGNED PA");
        when(objectDao.getById(anyInt())).thenReturn(object);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_suballocated_pa_slash16domain_slash16inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.0 - 102.2.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.2.0.0 - 102.2.255.255"));


        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);


        final RpslObject object = RpslObject.parse("inetnum: 102.2.0.0 - 102.2.255.255" +
                "\nstatus: SUB-ALLOCATED PA");
        when(objectDao.getById(anyInt())).thenReturn(object);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_allocated_pa_with_children_slash16domain_slash14inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0 - 102.3.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final RpslObject object = RpslObject.parse("inetnum: 102.0.0.0 - 102.3.255.255" +
                "\nstatus: ALLOCATED PA");

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.0.0.0 - 102.3.255.255"));

        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);
        when(objectDao.getById(anyInt())).thenReturn(object);

        when(ipv4Tree.findFirstMoreSpecific(Ipv4Resource.parse("102.0.0.0/14"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.2.0.10 - 102.2.0.12"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.2.1/24"), 2)
        ));

        subject.validate(update, updateContext);

        verifyNoMoreInteractions(updateContext);
    }

    @Test
    public void validate_allocated_pa_no_children_slash16domain_slash14inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.102.in-addr.arpa"));

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.2.0.0/16"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0 - 102.3.255.255"), 1),
                new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 2)
        ));

        final RpslObject object = RpslObject.parse("inetnum: 102.0.0.0 - 102.3.255.255" +
                "\nstatus: ALLOCATED PA");

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.0.0.0 - 102.3.255.255"));

        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);
        when(objectDao.getById(anyInt())).thenReturn(object);

        when(ipv4Tree.findFirstMoreSpecific(Ipv4Resource.parse("102.0.0.0/14"))).thenReturn(new ArrayList<Ipv4Entry>());

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.noMoreSpecificInetnumFound(object.toString()));

    }

    @Test
    public void validate_assigned_pa_slash24domain_slash24inetnum() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 1.5.102.in-addr.arpa"));

        final RpslObject object = RpslObject.parse("inetnum: 102.5.1.0 - 102.5.1.255" +
                "\nstatus: ASSIGNED PA");

        when(ipv4Tree.findExactOrFirstLessSpecific(Ipv4Resource.parse("102.5.1.0/24"))).thenReturn(Lists.newArrayList(
                new Ipv4Entry(Ipv4Resource.parse("102.5.1.0 - 102.5.1.255"), 1)
        ));

        final List<RpslObjectInfo> rpslObjectInfoList = new ArrayList<RpslObjectInfo>();
        rpslObjectInfoList.add(new RpslObjectInfo(0, ObjectType.INETNUM, "102.5.1.0 - 102.5.1.255"));

        when(objectDao.findByAttribute(any(AttributeType.class), any(String.class))).thenReturn(rpslObjectInfoList);
        when(objectDao.getById(anyInt())).thenReturn(object);

        subject.validate(update, updateContext);

        verifyNoMoreInteractions(updateContext);
    }

}
