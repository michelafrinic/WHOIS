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
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.*;
import net.ripe.db.whois.update.rest.SubAllocationWindowRESTCaller;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.verification.VerificationMode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.contains;
import static org.mockito.Matchers.any;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SubAllocationWindowValidatorTest {
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;
    @Mock
    SubAllocationWindowRESTCaller subAllocationWindowRESTCaller;
    @Mock
    RpslObjectUpdateDao rpslObjectUpdateDao;
    @Mock
    RpslObjectDao rpslObjectDao;
    @Mock
    Ipv4Tree ipv4Tree;
    @Mock
    Subject hostMasterSubject;
    @InjectMocks
    SubAllocationWindowValidator subject;

    @Test
    public void getActions() {
        assertThat(subject.getActions(), contains(Action.CREATE));
    }

    @Test
    public void getTypes() {
        assertThat(subject.getTypes(), contains(ObjectType.INETNUM));
    }

    @Test
    public void validate_OtherThanAssignedSubAllocatedPA() {
        InetnumStatus[] inetnumStatuses = InetnumStatus.values();

        for (int i = 0; i < inetnumStatuses.length; i++) {
            InetnumStatus status = inetnumStatuses[i];

            if (!status.equals(InetnumStatus.SUB_ALLOCATED_PA)) {
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
    public void verifyNoReferencedOrganisation() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n"));
        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.orgAttributeMissing());
    }

    @Test
    public void verifyReferencedOrganisationIsNotALIR() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: RIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.onlyLIRCanCreateSubAllocations());
    }

    @Test
    public void verifyNoSubAllocationSpecified() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(null);

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.noSubAllocationSpecified());
    }

    @Test
    public void verifySubAllocationNotAllowed() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(-1));
        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(updateContext.getSubject(any(Update.class))).thenReturn(hostMasterSubject);
        when(hostMasterSubject.isHostmaster()).thenReturn(false);

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.subAllocationNotAllowed());
    }

    @Test
    public void verifySubAllocationZeroNoHostmaster() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(0));
        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(updateContext.getSubject(any(Update.class))).thenReturn(hostMasterSubject);
        when(hostMasterSubject.isHostmaster()).thenReturn(false);

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.onlyHostMasterCanCreateSubAllocationWhenSAWNull());
    }

    @Test
    public void verifySubAllocationZeroWithHostmaster() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(0));
        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(updateContext.getSubject(any(Update.class))).thenReturn(hostMasterSubject);
        when(hostMasterSubject.isHostmaster()).thenReturn(true);

        subject.validate(update, updateContext);
        verify(updateContext, only()).getSubject(any(Update.class));
    }

    @Test
    public void verifyRangeTooLow() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.7.125 - 193.0.7.125\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(24));

        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.invalidPrefixLengthRange(32, 24, 16));
    }

    @Test
    public void verifyRangeHigherThanParent() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.255.255.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(24));

        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.invalidPrefixLengthRange(8, 24, 16));
    }

    @Test
    public void verifyRangeTooHighForSAW() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(24));

        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.rangeTooHighForStatusSAW(Integer.valueOf(24), 21));
    }

    @Test
    public void verifySubAllocationSuccess() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(16));

        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(updateContext.getSubject(any(Update.class))).thenReturn(hostMasterSubject);
        when(hostMasterSubject.isHostmaster()).thenReturn(false);

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void verifySubAllocationSuccessWithHostmaster() {
        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        193.0.0.0 - 193.0.7.255\n" +
                "netname:        AFRINIC\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "status:         SUB-ALLOCATED PA\n");

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: LIR\n");

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(subAllocationWindowRESTCaller.getSAW4(any(String.class))).thenReturn(Integer.valueOf(16));

        final Ipv4Entry entry = new Ipv4Entry(Ipv4Resource.parse("193.0/16"), 2);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.<Ipv4Entry>newArrayList(entry));
        when(updateContext.getSubject(any(Update.class))).thenReturn(hostMasterSubject);
        when(hostMasterSubject.isHostmaster()).thenReturn(true);

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }
}
