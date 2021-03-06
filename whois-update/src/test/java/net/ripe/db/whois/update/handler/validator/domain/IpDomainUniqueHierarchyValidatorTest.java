package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.iptree.*;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class IpDomainUniqueHierarchyValidatorTest {
    @Mock UpdateContext updateContext;
    @Mock PreparedUpdate update;

    @Mock Ipv4DomainTree ipv4DomainTree;
    @Mock Ipv6DomainTree ipv6DomainTree;
    @Mock
    ExcludedResources excludedResources;
    @InjectMocks IpDomainUniqueHierarchyValidator subject;

    @Test
    public void getActions() {
        assertThat(subject.getActions(), containsInAnyOrder(Action.CREATE));
    }

    @Test
    public void getTypes() {
        assertThat(subject.getTypes(), containsInAnyOrder(ObjectType.DOMAIN));
    }

    @Test
    public void validate_enum() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));

        subject.validate(update, updateContext);

        verifyZeroInteractions(ipv4DomainTree, ipv6DomainTree);
    }

    @Test
    public void validate_ipv4_domain_success() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 200.193.193.in-addr.arpa"));

        subject.validate(update, updateContext);

        verify(ipv4DomainTree).findFirstLessSpecific(Ipv4Resource.parse("193.193.200.0/24"));
        verify(ipv4DomainTree).findFirstMoreSpecific(Ipv4Resource.parse("193.193.200.0/24"));

        verifyZeroInteractions(ipv6DomainTree);
    }

    @Test
    public void validate_ipv6_domain_success() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa"));

        subject.validate(update, updateContext);

        verify(ipv6DomainTree).findFirstLessSpecific(Ipv6Resource.parse("2001:7f8::/48"));
        verify(ipv6DomainTree).findFirstMoreSpecific(Ipv6Resource.parse("2001:7f8::/48"));

        verifyZeroInteractions(ipv4DomainTree);
    }

    @Test
    public void validate_ipv4_domain_less_specific() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 200.193.196.in-addr.arpa"));

        final Ipv4Resource lessSpecific = Ipv4Resource.parse("196/8");
        Ipv4Entry ipv4Entry = new Ipv4Entry(lessSpecific, 1);

        when(ipv4DomainTree.findFirstLessSpecific(Ipv4Resource.parse("196.193.200.0/24"))).thenReturn(Lists.newArrayList(ipv4Entry));
        when(excludedResources.isExcluded(ipv4Entry)).thenReturn(true);

        subject.validate(update, updateContext);

        verifyZeroInteractions(ipv6DomainTree);
    }

    @Test
    public void validate_ipv4_domain_more_specific() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 200.193.193.in-addr.arpa"));

        final Ipv4Resource moreSpecific = Ipv4Resource.parse("193.193.200.0/32");

        when(ipv4DomainTree.findFirstMoreSpecific(Ipv4Resource.parse("193.193.200.0/24"))).thenReturn(Lists.newArrayList(new Ipv4Entry(moreSpecific, 1)));

        subject.validate(update, updateContext);

        verify(updateContext).addMessage(update, UpdateMessages.moreSpecificDomainFound(moreSpecific.toString()));
        verifyZeroInteractions(ipv6DomainTree);
    }

    @Test
    public void validate_ipv4_domain_less_specific_slash8_success() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 140.192.196.in-addr.arpa"));

        final Ipv4Resource lessSpecific = Ipv4Resource.parse("196/8");
        Ipv4Entry ipv4Entry = new Ipv4Entry(lessSpecific, 1);

        when(ipv4DomainTree.findFirstLessSpecific(Ipv4Resource.parse("196.192.140.0/24"))).thenReturn(Lists.newArrayList(ipv4Entry));
        when(excludedResources.isExcluded(ipv4Entry)).thenReturn(true);

        subject.validate(update, updateContext);

        verify(updateContext, never()).addMessage(any(PreparedUpdate.class), any(Message.class));
        verifyZeroInteractions(ipv6DomainTree);
    }

    @Test
    public void validate_ipv6_domain_less_specific_slashlessthan24_success() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain: 0.0.0.0.8.f.3.4.1.0.0.2.ip6.arpa"));

        final Ipv6Resource lessSpecific = Ipv6Resource.parse("2001:4300::/24");

        final Ipv6Entry ipv6Entry = new Ipv6Entry(lessSpecific,anyInt());
        final List<Ipv6Entry> ipv6EntryList = new ArrayList<>();
        ipv6EntryList.add(ipv6Entry);

        when(ipv6DomainTree.findFirstLessSpecific(Ipv6Resource.parse("2001:4300::/48"))).thenReturn(ipv6EntryList);
        when(excludedResources.isExcluded(ipv6Entry)).thenReturn(true);

        subject.validate(update, updateContext);

        verify(updateContext, never()).addMessage(any(PreparedUpdate.class), any(Message.class));
        verifyZeroInteractions(ipv4DomainTree);
    }
}
