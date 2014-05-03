package net.ripe.db.whois.common.domain;

import com.google.common.collect.Sets;
import net.ripe.db.whois.common.etree.Interval;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class IpRanges {
    private static final Logger LOGGER = LoggerFactory.getLogger(IpRanges.class);

    private Set<Interval> trusted;
    private Set<Interval> hostmaster;
    private Set<Interval> loadbalancers;

    @Value("${ipranges.trusted}")
    public void setTrusted(final String... trusted) {
        this.trusted = getIntervals(trusted);
        LOGGER.info("Trusted ranges: {}", this.trusted);
    }

    @Value("${ipranges.hostmaster}")
    public void setHostmaster(final String... hostmaster) {
        this.hostmaster = getIntervals(hostmaster);
        LOGGER.info("Hostmaster ranges: {}", this.hostmaster);
    }

    public boolean isTrusted(final Interval ipResource) {
        return contains(ipResource, trusted);
    }
    public boolean isHostmaster(final Interval ipResource) {
        return contains(ipResource, hostmaster);
    }

    @Value("${ipranges.loadbalancer}")
    public void setLoadbalancers(final String... loadbalancers) {
        this.loadbalancers = getIntervals(loadbalancers);
        LOGGER.info("Loadbalancer ranges: {}", this.loadbalancers);
    }

    public boolean isLoadbalancer(final Interval ipResource) {
        return contains(ipResource, loadbalancers);
    }

    private Set<Interval> getIntervals(String[] trusted) {
        final Set<Interval> ipResources = Sets.newLinkedHashSetWithExpectedSize(trusted.length);
        for (final String trustedRange : trusted) {
            ipResources.add(IpInterval.parse(trustedRange));
        }
        return ipResources;
    }

    private boolean contains(Interval ipResource, Set<Interval> ipRanges) {
        for (final Interval resource : ipRanges) {
            if (resource.getClass().equals(ipResource.getClass()) && resource.contains(ipResource)) {
                return true;
            }
        }

        return false;
    }
}
