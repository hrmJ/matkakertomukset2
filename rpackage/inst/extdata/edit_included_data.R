

fsstats1$asuminen_expressed <- gsub(";.*","",fsstats1$asuminen_expressed)
fsstats1$indicatorword <- gsub(";.*","",fsstats1$indicatorword)
fsstats1$head_of_indicator <- gsub(";.*","",fsstats1$head_of_indicator)
fsstats1$head_of_indicator_loc <- gsub(";.*","",fsstats1$head_of_indicator_loc)
fsstats1$indicatorloc <- gsub(";.*","",fsstats1$indicatorloc)
fsstats1$indicator_ratio  <- round(fsstats1$indicatorwords / fsstats1$words_total * 100,2)

withindicator$asuminen_expressed <- gsub(";.*","",withindicator$asuminen_expressed)
withindicator$indicatorword <- gsub(";.*","",withindicator$indicatorword)
withindicator$head_of_indicator <- gsub(";.*","",withindicator$head_of_indicator)
withindicator$head_of_indicator_loc <- gsub(";.*","",withindicator$head_of_indicator_loc)
withindicator$indicatorloc <- gsub(";.*","",withindicator$indicatorloc)
withindicator$indicator_ratio  <- round(withindicator$indicatorwords / withindicator$words_total * 100,2)
withindicator$indicator_ratio  <- round(withindicator$indicatorwords / withindicator$words_total * 100,2)
withindicator$indicator.deprel <- factor(withindicator$asuminen_expressed,levels=unique(names(sort(table(withindicator$asuminen_expressed),d=T))))

fsstats1$headverb_person_simple <- "--"
fsstats1$headverb_person_simple[grepl("1",fsstats1$headverb_person)] <- "1p"
fsstats1$headverb_person_simple[grepl("3",fsstats1$headverb_person)] <- "3p"
fsstats1$headverb_person_simple[which(fsstats1$headverb_person=="")] <- "--"
fsstats1$indicatorword_length <-  str_length(fsstats1$indicatorword_token) 

save(fsstats1, file="rpackage/data/fsstats1.rda")
save(withindicator, file="rpackage/data/withindicator.rda")

#SATUNNAISOTANTA

withindicator.1s <- subset(withindicator,sentence_number==1)
withindicator.1s$indicator.deprel <- as.character(withindicator.1s$indicator.deprel)
withindicator.1s$indicator.deprel[withindicator.1s$indicator.deprel %in% names(table(withindicator.1s$indicator.deprel)[table(withindicator.1s$indicator.deprel)<10])] <- "Muu"
withindicator.1s$indicator.deprel <- factor(withindicator.1s$indicator.deprel,levels=unique(names(sort(table(withindicator.1s$indicator.deprel),d=T))))
tab <- as.data.frame(sort(table(withindicator.1s$indicator.deprel),dec=T))
tab$sample <- round(tab$Freq/2)
colnames(tab) <- c("Kategoria","Yht.","Otanta")


set.seed(9^9)
otannat_analyysiin <- list()
for(kat in tab$Kategoria){
    no  <- tab[tab$Kategoria==kat,"Otanta"]
    thisdf <- subset(withindicator.1s,indicator.deprel==kat)
    otannat_analyysiin[[kat]] <- thisdf[sample(c(1:nrow(thisdf)),size=no),]
}
otannat_analyysiin <- do.call("rbind", otannat_analyysiin)

save(otannat_analyysiin, file="rpackage/data/otannat_analyysin.rda")


#tarkempia tietoja:


alatopiikkiAnalyysi <- subset(otannat_analyysiin,select=c("sentence","paragraph","textid","indicatorword","indicator.deprel","headverb_lemma","headverb_person","words_total"))
alatopiikkiAnalyysi$edellinenkpl <- sapply(alatopiikkiAnalyysi$textid,function(x,d)d$previous_paragraph[d$textid==x] ,d=previous_pars)
alatopiikkiAnalyysi$valiotsikko <- sapply(alatopiikkiAnalyysi$textid,function(x,d)d$chaptertitle[d$textid==x] ,d=chaptertitles)
write.xlsx(alatopiikkiAnalyysi,"data/alatopiikkianalyysi.xlsx")


