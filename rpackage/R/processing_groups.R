
#' Hae data ryhmistä yaml-tiedostojen perusteella
#' @importFrom yaml yaml.load_file
#' @export

GetGroupsFromYaml <- function(otanta){

    # ryhmien nimet
    grouplist <- setNames(lapply(list.files("data/groups/"),function(x)return(yaml.load_file(paste0("data/groups/",x)))),list.files("data/groups/"))
    cc<-lapply(grouplist,function(x)return(list(Nimi=x$Nimi,Kuvaus=x$Kuvaus,"Yläotsikko"=x$ylaotsikko)))
    groups.meta <- as.data.frame(t(as.data.frame(do.call(cbind,cc))))
    for(cname in colnames(groups.meta)){
        groups.meta[[cname]] <- unlist(groups.meta[[cname]])
    }
    # ryhmien numeron merkkaaminen dataframeen
    otanta$group  <- ""
    for(g in grouplist){
        for (textid in g$textid){
          otanta$group[otanta$textid==textid$id] <- g$Nimi
        }
    }
    return(otanta)
}


SetMissingGroup <- function(){
    
    unlist(groups.meta$Nimi)

}
