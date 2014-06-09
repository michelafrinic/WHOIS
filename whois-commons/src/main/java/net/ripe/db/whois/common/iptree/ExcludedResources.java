package net.ripe.db.whois.common.iptree;

import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.etree.IntervalMap;
import net.ripe.db.whois.common.etree.NestedIntervalMap;
import net.ripe.db.whois.common.etree.SynchronizedIntervalMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by michel on 6/5/14.
 */
@Component
public class ExcludedResources {
    private List<Ipv4Resource> ipv4ResourcesToExclude = new ArrayList<Ipv4Resource>();
    private List<Ipv6Resource> ipv6ResourcesToExclude = new ArrayList<Ipv6Resource>();

    @Autowired
    public ExcludedResources(
            @Value("${whois.inetnum.exclude.ipv4}") final String[] ipv4ParentDomainToExclude,
            @Value("${whois.inetnum.exclude.ipv6}") final String[] ipv6ParentDomainToExclude) {
        for (int i = 0; i < ipv4ParentDomainToExclude.length; i++) {
            ipv4ResourcesToExclude.add(Ipv4Resource.parse(ipv4ParentDomainToExclude[i]));
        }

        for (int i = 0; i < ipv6ParentDomainToExclude.length; i++) {
            ipv6ResourcesToExclude.add(Ipv6Resource.parse(ipv6ParentDomainToExclude[i]));
        }
    }

    public List<Ipv4Resource> getIpv4ResourcesToExclude() {
        return ipv4ResourcesToExclude;
    }

    public List<Ipv6Resource> getIpv6ResourcesToExclude() {
        return ipv6ResourcesToExclude;
    }

    private boolean isExcluded(Ipv4Entry entry) {
        for(Ipv4Resource resource : ipv4ResourcesToExclude) {
            if(resource.contains(entry.getKey())) {
                return true;
            }
        }
        return false;
    }

    private boolean isExcluded(Ipv6Entry entry) {
        for(Ipv6Resource resource : ipv6ResourcesToExclude) {
            if(resource.contains(entry.getKey())) {
                return true;
            }
        }
        return false;
    }

    public List<Ipv4Entry> removeV4Excluded(List<Ipv4Entry> list) {
        List<Ipv4Entry> returnList = new ArrayList<Ipv4Entry>();
        for(Ipv4Entry entry : list) {
            if(!isExcluded(entry)) {
                returnList.add(entry);
            }
        }
        return returnList;
    }

    public List<Ipv6Entry> removeV6Excluded(final List<Ipv6Entry> list) {
        List<Ipv6Entry> returnList = new ArrayList<Ipv6Entry>();
        for(Ipv6Entry entry : list) {
            if(!isExcluded(entry)) {
                returnList.add(entry);
            }
        }
        return returnList;
    }
}
