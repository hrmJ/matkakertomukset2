
#' List the different deprels as separate data frames
#' @return the list with the data frames
#' @export
GetListOfDepRels <- function(){
    deprels <- list(dobj = list(df=subset(withindicator,asuminen_expressed=="dobj")),
                    root   = list(df=subset(withindicator,asuminen_expressed=="root")),
                    nsubj  = list(df=subset(withindicator,asuminen_expressed=="nsubj")),
                    nmposs = list(df=subset(withindicator,asuminen_expressed=="nmod:poss")),
                    nscop  = list(df=subset(withindicator,asuminen_expressed=="nsubj:cop")),
                    xcomp  = list(df=subset(withindicator,asuminen_expressed=="xcomp")),
                    nmod   = list(df=subset(withindicator,asuminen_expressed=="nmod")),
                    gobj   = list(df=subset(withindicator,asuminen_expressed=="nmod:gobj")),
                    props  = round(100*prop.table(sort(table(withindicator$indicator.deprel),d=T)))
                    )
    for(deprel in names(deprels)){
        if(deprel != "props"){
            deprels[[deprel]] <- VerbInfo(deprels[[deprel]])
            deprels[[deprel]]$indicatorprops <- round(100*prop.table(table(deprels[[deprel]]$df$indicatorword)))
        }
    }
    return(deprels)
}
