
test <- analysoitu_otanta
test$id <- rownames(test)
test$title  <- test$sentence

# Etsi joka ryhmän ekat

fromlist <- setNames(lapply(unique(test$group),function(g,te) return(which(te$group==g)),te=test),unique(test$group))
from <- c();to <- c()
for(x in fromlist){
    from <- c(from,rep(x[1],length(x)-1))
    to <- c(to,x[c(2:length(x))])
}
edges <- data.frame(from =from, to = to)

visNetwork(test, edges, width = "100%", height="20cm") %>% 
      visGroups(groupname = "Listamaiset", color = "darkblue", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Yliopisto (maggy) tarjosi", color = "red", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Kontrasti", color = "yellow", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Ennakoivat", color = "green", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "yleistys", color = "purple", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "asunnon ja asumisen staattinen kuvailu", color = "brown", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Selkeät yksittäiseen tapahtumaan keskittyvät narratiivit", color = "pink", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "oma kokemus", color = "blue", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "ennakoivien ja predikoivien välimaasto", color = "darkyellow", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "asuin paikassa x", color = "cyan", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Suurin osa opiskelijoista", color = "beige", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "Linkki", color = "grey", shape = "circle", shadow = list(enabled = TRUE)) %>%
      visGroups(groupname = "pari sanaa asumisesta", color = "salmon", shape = "circle", shadow = list(enabled = TRUE))   %>%
      visClusteringByGroup(groups = unique(test$group),label="") 
