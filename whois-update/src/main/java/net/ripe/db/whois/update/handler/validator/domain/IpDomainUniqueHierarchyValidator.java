package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.iptree.*;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class IpDomainUniqueHierarchyValidator implements BusinessRuleValidator {
    private final Ipv4DomainTree ipv4DomainTree;
    private final Ipv6DomainTree ipv6DomainTree;
    private String [] ipv4ParentDomainToExclude;
    private String [] ipv6ParentDomainToExclude;

    @Autowired
    public IpDomainUniqueHierarchyValidator(final Ipv4DomainTree ipv4DomainTree, final Ipv6DomainTree ipv6DomainTree) {
        this.ipv4DomainTree = ipv4DomainTree;
        this.ipv6DomainTree = ipv6DomainTree;
    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.DOMAIN);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        final Domain domain = Domain.parse(update.getUpdatedObject().getKey());
        if (domain.getType() == Domain.Type.E164) {
            return;
        }

        final IpInterval reverseIp = domain.getReverseIp();
        final IpTree ipTree = getIpTree(reverseIp);

        final List<IpEntry> lessSpecific = ipTree.findFirstLessSpecific(reverseIp);
        if (!lessSpecific.isEmpty()) {
            IpEntry ipEntry = lessSpecific.get(0);

            if(domain.getType() == Domain.Type.INADDR) {
                Ipv4Entry entry = (Ipv4Entry) ipEntry;

                for (int i=0; i<ipv4ParentDomainToExclude.length;i++) {
                    if (entry.getKey().intersects(Ipv4Resource.parse(ipv4ParentDomainToExclude[i]))) {
                        return;
                    }
                }


            }else {
                Ipv6Entry entry = (Ipv6Entry) ipEntry;

                for (int i=0; i<ipv6ParentDomainToExclude.length;i++) {
                    if (entry.getKey().intersects(Ipv6Resource.parse(ipv6ParentDomainToExclude[i]))) {
                        return;
                    }
                }

            }

            updateContext.addMessage(update, UpdateMessages.lessSpecificDomainFound(ipEntry.getKey().toString()));
            return;
        }

        final List<IpEntry> moreSpecific = ipTree.findFirstMoreSpecific(reverseIp);
        if (!moreSpecific.isEmpty()) {
            updateContext.addMessage(update, UpdateMessages.moreSpecificDomainFound(moreSpecific.get(0).getKey().toString()));
        }
    }

    private IpTree getIpTree(final IpInterval reverseIp) {
        if (reverseIp instanceof Ipv4Resource) {
            return ipv4DomainTree;
        } else if (reverseIp instanceof Ipv6Resource) {
            return ipv6DomainTree;
        }

        throw new IllegalArgumentException("Unexpected reverse ip: " + reverseIp);
    }


    @Value("${whois.domain.exclude.ipv4}")
    public void setIpv4ParentDomainToExclude(final String[] ipv4ParentDomainToExclude) {
        this.ipv4ParentDomainToExclude = new String[ipv4ParentDomainToExclude.length];
        System.arraycopy(ipv4ParentDomainToExclude, 0, this.ipv4ParentDomainToExclude, 0, ipv4ParentDomainToExclude.length);
    }

    @Value("${whois.domain.exclude.ipv6}")
    public void setIpv6ParentDomainToExclude(final String[] ipv6ParentDomainToExclude) {
        this.ipv6ParentDomainToExclude = new String[ipv6ParentDomainToExclude.length];
        System.arraycopy(ipv6ParentDomainToExclude, 0, this.ipv6ParentDomainToExclude, 0, ipv6ParentDomainToExclude.length);
    }
}
