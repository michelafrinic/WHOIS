package net.ripe.db.whois.update.handler.validator.inetnum;

import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.*;
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
    RpslObject rpslObject;
    @Mock
    Ipv4Tree ipv4Tree;
    @Mock
    Maintainers maintainers;
    @InjectMocks
    AssignedAnycastStatusValidator subject;

    @Test
    public void getActions() {
        assertThat(subject.getActions(), contains(Action.CREATE,Action.MODIFY));
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

    @Test
    public void checkInetnumEndUserParentOfWrongStatusFails() {

        InetnumStatus[] inetnumStatuses = InetnumStatus.values();

        for (int i = 0; i < inetnumStatuses.length; i++) {
            InetnumStatus status = inetnumStatuses[i];

            if (!status.equals(InetnumStatus.ASSIGNED_ANYCAST) && !status.equals(InetnumStatus.ALLOCATED_UNSPECIFIED)) {

                RpslObject inetnum = RpslObject.parse("" +
                        "inetnum:        102.100.255.0/24\n" +
                        "netname:        AFRINIC\n" +
                        "status:         ASSIGNED ANYCAST\n" +
                        "org:            ORG-SA56-AFRINIC");

                List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();

                RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

                RpslObject organisationRpslObject = RpslObject.parse("" +
                        "organisation:  ORG-SA56-AFRINIC\n" +
                        "org-type: EU_PI\n");

                Ipv4Entry ipv4EntryParent = new Ipv4Entry(Ipv4Resource.parse("102.100.0.0/16"), 1);
                List<Ipv4Entry> parents = new ArrayList<Ipv4Entry>();
                parents.add(ipv4EntryParent);

                RpslObject inetnumParent = RpslObject.parse("" +
                        "inetnum:        102.100.0.0/16\n" +
                        "netname:        AFRINIC\n" +
                        "status:         " + status.toString() + "\n" +
                        "org:            ORG-SA56-AFRINIC");

                when(update.getUpdatedObject()).thenReturn(inetnum);
                when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);
                when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
                when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
                when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parents);
                when(rpslObjectDao.getById(1)).thenReturn(inetnumParent);

                subject.validate(update, updateContext);

                verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastEUInvalidParentStatus());
                reset(update, updateContext); // to avoid incrementing the invocations number at every loop
            }
        }
    }

    @Test
    public void checkInetnumEndUserWithoutMNntByFails() {

        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.0/24\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-SA56-AFRINIC");

        List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: EU_PI\n");

        Ipv4Entry ipv4EntryParent = new Ipv4Entry(Ipv4Resource.parse("102.100.0.0/16"), 1);
        List<Ipv4Entry> parents = new ArrayList<Ipv4Entry>();
        parents.add(ipv4EntryParent);

        RpslObject inetnumParent = RpslObject.parse("" +
                "inetnum:        102.100.0.0/16\n" +
                "netname:        AFRINIC\n" +
                "status:         ALLOCATED UNSPECIFIED\n" +
                "org:            ORG-SA56-AFRINIC");

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parents);
        when(rpslObjectDao.getById(1)).thenReturn(inetnumParent);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastEUInvalidMntByStatus("AFRINIC-HM-MNT"));
    }

    @Test
    public void checkInetnumEndUserNotAuthentifiedByAPowerMaintainerFails() {

        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.0/24\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "mnt-by:         SOMEONE");

        List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: EU_PI\n");

        Ipv4Entry ipv4EntryParent = new Ipv4Entry(Ipv4Resource.parse("102.100.0.0/16"), 1);
        List<Ipv4Entry> parents = new ArrayList<Ipv4Entry>();
        parents.add(ipv4EntryParent);

        RpslObject inetnumParent = RpslObject.parse("" +
                "inetnum:        102.100.0.0/16\n" +
                "netname:        AFRINIC\n" +
                "status:         ALLOCATED UNSPECIFIED\n" +
                "org:            ORG-SA56-AFRINIC");

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parents);
        when(rpslObjectDao.getById(1)).thenReturn(inetnumParent);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastEUInvalidMntByStatus("AFRINIC-HM-MNT"));
    }

    @Test
    public void checkInetnumWithoutParentEndUserSuccess() {

        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.0/24\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT");

        List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: EU_PI\n");

        List<Ipv4Entry> parents = new ArrayList<Ipv4Entry>();

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parents);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void checkInetnumEndUserSuccess() {

        RpslObject inetnum = RpslObject.parse("" +
                "inetnum:        102.100.255.0/24\n" +
                "netname:        AFRINIC\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-SA56-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT");

        List<Ipv4Entry> children = new ArrayList<Ipv4Entry>();

        RpslObjectInfo organisationRpslObjectInfo = new RpslObjectInfo(1, ObjectType.ORGANISATION, CIString.ciString("ORG-SA56-AFRINIC"));

        RpslObject organisationRpslObject = RpslObject.parse("" +
                "organisation:  ORG-SA56-AFRINIC\n" +
                "org-type: EU_PI\n");

        Ipv4Entry ipv4EntryParent = new Ipv4Entry(Ipv4Resource.parse("102.100.0.0/16"), 1);
        List<Ipv4Entry> parents = new ArrayList<Ipv4Entry>();
        parents.add(ipv4EntryParent);

        RpslObject inetnumParent = RpslObject.parse("" +
                "inetnum:        102.100.0.0/16\n" +
                "netname:        AFRINIC\n" +
                "status:         ALLOCATED UNSPECIFIED\n" +
                "org:            ORG-SA56-AFRINIC");

        Set<CIString> powerMaintainers = new HashSet<CIString>();
        powerMaintainers.add(CIString.ciString("AFRINIC-HM-MNT"));

        when(update.getUpdatedObject()).thenReturn(inetnum);
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(children);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(organisationRpslObjectInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-SA56-AFRINIC")).thenReturn(organisationRpslObject);
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parents);
        when(rpslObjectDao.getById(1)).thenReturn(inetnumParent);
        when(maintainers.getPowerMaintainers()).thenReturn(powerMaintainers);

        subject.validate(update, updateContext);

        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_LirSuccess_InetnumHasOrg() {

        // Mock behaviour: inetnum = /24
        //                 inetnum.status = ASSIGNED ANYCAST
        //                 inetnum.org exists
        //                 inetnum.mnt-by exists
        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
        "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no child
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.org.org-type = LIR
        CIString referencedOrgKey = CIString.ciString("ORG-EB2-AFRINIC");
        RpslObjectInfo referencedOrgInfo = new RpslObjectInfo(1230, ObjectType.ORGANISATION, referencedOrgKey);
        RpslObject referencedOrg = RpslObject.parse("" +
                "organisation:   ORG-EB2-AFRINIC\n" +
                "org-type:       LIR\n" +
        "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, referencedOrgKey))
                .thenReturn(referencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, referencedOrgInfo.getKey()))
                .thenReturn(referencedOrg);

        // Mock behaviour: inetnum.parent.status = ALLOCATED PA
        //                 inetnum.parent.mnt-lower = inetnum.mnt-by
        //                 inetnum.parent.org exists
        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ALLOCATED PA\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "org:            ORG-AFNC1-AFRINIC\n" +
        "");
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);
        when(rpslObjectDao.getById(parentIpTreeEntry.getObjectId())).thenReturn(parentInetnum);

        // Mock behaviour: inetnum.parent.org.org-type = LIR
        CIString parentReferencedOrgKey = CIString.ciString("ORG-AFNC1-AFRINIC");
        RpslObjectInfo parentReferencedOrgInfo = new RpslObjectInfo(1232, ObjectType.ORGANISATION, parentReferencedOrgKey);
        RpslObject parentReferencedOrg = RpslObject.parse("" +
                "organisation:   ORG-AFNC1-AFRINIC\n" +
                "org-type:       LIR\n" +
        "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, parentReferencedOrgKey))
                .thenReturn(parentReferencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, parentReferencedOrgInfo.getKey()))
                .thenReturn(parentReferencedOrg);

        // Test
        subject.validate(update, updateContext);

        // Verify method calls
        verify(update, times(2)).getUpdatedObject();
        verify(ipv4Tree, times(1)).findAllMoreSpecific(any(Ipv4Resource.class));
        verify(ipv4Tree, times(1)).findFirstLessSpecific(any(Ipv4Resource.class));
        verify(rpslObjectDao, times(2)).getByKey(eq(ObjectType.ORGANISATION), any(String.class));
        verify(rpslObjectDao, times(1)).getById(anyInt());
        verify(rpslObjectUpdateDao, times(2)).getAttributeReference(eq(AttributeType.ORG), any(CIString.class));

        // Verify that no error message has been generated
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_LirSuccess_InetnumHasNoOrg() {

        // Mock behaviour: inetnum = /24
        //                 inetnum.status = ASSIGNED ANYCAST
        //                 inetnum.org does not exist
        //                 inetnum.mnt-by exists
        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no child
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.parent.status = ALLOCATED PA
        //                 inetnum.parent.mnt-lower = inetnum.mnt-by
        //                 inetnum.parent.org exists
        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ALLOCATED PA\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "org:            ORG-AFNC1-AFRINIC\n" +
                "");
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);
        when(rpslObjectDao.getById(parentIpTreeEntry.getObjectId())).thenReturn(parentInetnum);

        // Mock behaviour: inetnum.parent.org.org-type = LIR
        CIString parentReferencedOrgKey = CIString.ciString("ORG-AFNC1-AFRINIC");
        RpslObjectInfo parentReferencedOrgInfo = new RpslObjectInfo(1232, ObjectType.ORGANISATION, parentReferencedOrgKey);
        RpslObject parentReferencedOrg = RpslObject.parse("" +
                "organisation:   ORG-AFNC1-AFRINIC\n" +
                "org-type:       LIR\n" +
                "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, parentReferencedOrgKey))
                .thenReturn(parentReferencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, parentReferencedOrgInfo.getKey()))
                .thenReturn(parentReferencedOrg);

        // Test
        subject.validate(update, updateContext);

        // Verify method calls
        verify(update, times(2)).getUpdatedObject();
        verify(ipv4Tree, times(1)).findAllMoreSpecific(any(Ipv4Resource.class));
        verify(ipv4Tree, times(1)).findFirstLessSpecific(any(Ipv4Resource.class));
        verify(rpslObjectDao, times(1)).getByKey(eq(ObjectType.ORGANISATION), any(String.class));
        verify(rpslObjectDao, times(1)).getById(anyInt());
        verify(rpslObjectUpdateDao, times(1)).getAttributeReference(eq(AttributeType.ORG), any(CIString.class));

        // Verify that no error message has been generated
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_LirSuccess_InetnumHasNoOrg_InetnumHasMntLower() {

        // Mock behaviour: inetnum = /24
        //                 inetnum.status = ASSIGNED ANYCAST
        //                 inetnum.org does not exist
        //                 inetnum.mnt-by exists
        //                 inetnum.mnt-lower exists
        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "mnt-by:         OTHER-MNT\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no child
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.parent.status = ALLOCATED PA
        //                 inetnum.parent.mnt-lower = inetnum.mnt-lower
        //                 inetnum.parent.org exists
        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ALLOCATED PA\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "org:            ORG-AFNC1-AFRINIC\n" +
                "");
        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);
        when(rpslObjectDao.getById(parentIpTreeEntry.getObjectId())).thenReturn(parentInetnum);

        // Mock behaviour: inetnum.parent.org.org-type = LIR
        CIString parentReferencedOrgKey = CIString.ciString("ORG-AFNC1-AFRINIC");
        RpslObjectInfo parentReferencedOrgInfo = new RpslObjectInfo(1232, ObjectType.ORGANISATION, parentReferencedOrgKey);
        RpslObject parentReferencedOrg = RpslObject.parse("" +
                "organisation:   ORG-AFNC1-AFRINIC\n" +
                "org-type:       LIR\n" +
                "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, parentReferencedOrgKey))
                .thenReturn(parentReferencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, parentReferencedOrgInfo.getKey()))
                .thenReturn(parentReferencedOrg);

        // Test
        subject.validate(update, updateContext);

        // Verify method calls
        verify(update, times(2)).getUpdatedObject();
        verify(ipv4Tree, times(1)).findAllMoreSpecific(any(Ipv4Resource.class));
        verify(ipv4Tree, times(1)).findFirstLessSpecific(any(Ipv4Resource.class));
        verify(rpslObjectDao, times(1)).getByKey(eq(ObjectType.ORGANISATION), any(String.class));
        verify(rpslObjectDao, times(1)).getById(anyInt());
        verify(rpslObjectUpdateDao, times(1)).getAttributeReference(eq(AttributeType.ORG), any(CIString.class));

        // Verify that no error message has been generated
        verifyZeroInteractions(updateContext);
    }


    @Test
    public void validate_LirFailure_InetnumHasNoParent() {

        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no parent
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.org.org-type = LIR
        CIString referencedOrgKey = CIString.ciString("ORG-EB2-AFRINIC");
        RpslObjectInfo referencedOrgInfo = new RpslObjectInfo(1230, ObjectType.ORGANISATION, referencedOrgKey);
        RpslObject referencedOrg = RpslObject.parse("" +
                "organisation:   ORG-EB2-AFRINIC\n" +
                "org-type:       LIR\n" +
                "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, referencedOrgKey))
                .thenReturn(referencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, referencedOrgInfo.getKey()))
                .thenReturn(referencedOrg);

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());


        // Test
        subject.validate(update, updateContext);

        // Verify that
        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastLIRMustHaveParent());
    }


    @Test
    public void validate_LirFailure_InetnumHasParentOtherThanAllocatedPA() {

        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no parent
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.org.org-type = LIR
        CIString referencedOrgKey = CIString.ciString("ORG-EB2-AFRINIC");
        RpslObjectInfo referencedOrgInfo = new RpslObjectInfo(1230, ObjectType.ORGANISATION, referencedOrgKey);
        RpslObject referencedOrg = RpslObject.parse("" +
                "organisation:   ORG-EB2-AFRINIC\n" +
                "org-type:       LIR\n" +
                "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, referencedOrgKey))
                .thenReturn(referencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, referencedOrgInfo.getKey()))
                .thenReturn(referencedOrg);


        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ASSIGNED PI\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "org:            ORG-AFNC1-AFRINIC\n" +
                "");

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);

        when(rpslObjectDao.getById(anyInt())).thenReturn(parentInetnum);

        // Test
        subject.validate(update, updateContext);

        // Verify that
        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastLIRParentMustBeOfStatus(InetnumStatus.ALLOCATED_PA.toString()));
    }

    @Test
    public void validate_LirFailure_InetnumParentHasNoOrg() {

        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no parent
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ALLOCATED PA\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "");

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);

        when(rpslObjectDao.getById(anyInt())).thenReturn(parentInetnum);

        when(rpslObject.findAttributes(any(AttributeType.class))).thenReturn(new ArrayList<RpslAttribute>());

        // Test
        subject.validate(update, updateContext);

        // Verify that
        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastLIRParentMustHaveAReferencedOrg());
    }

    @Test
    public void validate_LirFailure_InetnumHasParentOrgTypeNotLIR() {

        RpslObject whoisObject = RpslObject.parse("" +
                "inetnum:        102.101.255.0/24\n" +
                "status:         ASSIGNED ANYCAST\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "");
        when(update.getUpdatedObject()).thenReturn(whoisObject);

        // Mock behaviour: inetnum has no parent
        when(ipv4Tree.findAllMoreSpecific(any(Ipv4Resource.class))).thenReturn(new ArrayList<Ipv4Entry>());

        // Mock behaviour: inetnum.org.org-type = LIR
        CIString referencedOrgKey = CIString.ciString("ORG-EB2-AFRINIC");
        RpslObjectInfo referencedOrgInfo = new RpslObjectInfo(1230, ObjectType.ORGANISATION, referencedOrgKey);
        RpslObject referencedOrg = RpslObject.parse("" +
                "organisation:   ORG-EB2-AFRINIC\n" +
                "org-type:       EU_AS\n" +
                "");
        when(rpslObjectUpdateDao.getAttributeReference(AttributeType.ORG, referencedOrgKey))
                .thenReturn(referencedOrgInfo);
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, referencedOrgInfo.getKey()))
                .thenReturn(referencedOrg);


        Ipv4Entry parentIpTreeEntry = new Ipv4Entry(Ipv4Resource.parse("102.0.0.0/8"), 1231);
        List<Ipv4Entry> parentIpTreeEntryInList = new ArrayList<Ipv4Entry>();
        parentIpTreeEntryInList.add(parentIpTreeEntry);
        RpslObject parentInetnum = RpslObject.parse("" +
                "inetnum:        102.0.0.0 - 102.255.255.255\n" +
                "status:         ALLOCATED PA\n" +
                "mnt-lower:      AFRINIC-HM-MNT\n" +
                "org:            ORG-EB2-AFRINIC\n" +
                "");

        when(ipv4Tree.findFirstLessSpecific(any(Ipv4Resource.class))).thenReturn(parentIpTreeEntryInList);

        when(rpslObjectDao.getById(anyInt())).thenReturn(parentInetnum);

        List<RpslAttribute> rpslAttributeList = new ArrayList<RpslAttribute>();

        rpslAttributeList.add(new RpslAttribute("ORGANISATION", "ORG-EB2-AFRINIC"));
        when(rpslObject.findAttributes(AttributeType.ORG)).thenReturn(rpslAttributeList);
        when(rpslObjectUpdateDao.getAttributeReference(any(AttributeType.class), any(CIString.class))).thenReturn(new RpslObjectInfo(1,ObjectType.ORGANISATION,"ORG-EB2-AFRINIC"));
        when(rpslObjectDao.getByKey(ObjectType.ORGANISATION, "ORG-EB2-AFRINIC")).thenReturn(referencedOrg);

        // Test
        subject.validate(update, updateContext);

        // Verify that
        verify(updateContext).addMessage(update, UpdateMessages.assignedAnycastLIRParentMustHaveAReferencedOrgOfTypeLIR());
    }
}
