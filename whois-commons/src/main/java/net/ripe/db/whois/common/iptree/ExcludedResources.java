package net.ripe.db.whois.common.iptree;

import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.etree.IntervalMap;
import net.ripe.db.whois.common.etree.NestedIntervalMap;
import net.ripe.db.whois.common.etree.SynchronizedIntervalMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Created by michel on 6/5/14.
 */
@Component
public final class ExcludedResources {
    private static List<Ipv4Resource> ipv4ResourcesToExclude = new ArrayList<Ipv4Resource>();
    private static List<Ipv6Resource> ipv6ResourcesToExclude = new ArrayList<Ipv6Resource>();

    private ExcludedResources() {}

    @Value("${whois.inetnum.exclude.ipv4}")
    public void setIpv4ParentDomainToExclude(final String[] ipv4ParentDomainToExclude) {
        for (int i = 0; i < ipv4ParentDomainToExclude.length; i++) {
            ipv4ResourcesToExclude.add(Ipv4Resource.parse(ipv4ParentDomainToExclude[i]));
        }
    }

    @Value("${whois.inetnum.exclude.ipv6}")
    public void setIpv6ParentDomainToExclude(final String[] ipv6ParentDomainToExclude) {
        for (int i = 0; i < ipv6ParentDomainToExclude.length; i++) {
            ipv6ResourcesToExclude.add(Ipv6Resource.parse(ipv6ParentDomainToExclude[i]));
        }
    }

    public static List<Ipv4Resource> getIpv4ResourcesToExclude() {
        return ipv4ResourcesToExclude;
    }

    public static List<Ipv6Resource> getIpv6ResourcesToExclude() {
        return ipv6ResourcesToExclude;
    }

    private static boolean isExcluded(Ipv4Entry entry) {
        for(Ipv4Resource resource : ipv4ResourcesToExclude) {
            if(resource.contains(entry.getKey())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isExcluded(Ipv6Entry entry) {
        for(Ipv6Resource resource : ipv6ResourcesToExclude) {
            if(resource.contains(entry.getKey())) {
                return true;
            }
        }
        return false;
    }

    public static List<Ipv4Entry> removeV4Excluded(List<Ipv4Entry> list) {
        List<Ipv4Entry> returnList = new ArrayList<Ipv4Entry>();
        for(Ipv4Entry entry : list) {
            if(!isExcluded(entry)) {
                returnList.add(entry);
            }
        }
        return returnList;
    }

    public static List<Ipv6Entry> removeV6Excluded(final List<Ipv6Entry> list) {
        List<Ipv6Entry> returnList = new ArrayList<Ipv6Entry>();
        for(Ipv6Entry entry : list) {
            if(!isExcluded(entry)) {
                returnList.add(entry);
            }
        }
        return returnList;
    }
}
