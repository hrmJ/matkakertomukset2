

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

fsstats1$headverb_person_simple <- "--"
fsstats1$headverb_person_simple[grepl("1",fsstats1$headverb_person)] <- "1p"
fsstats1$headverb_person_simple[grepl("3",fsstats1$headverb_person)] <- "3p"
fsstats1$headverb_person_simple[which(fsstats1$headverb_person=="")] <- "--"
fsstats1$indicatorword_length <-  str_length(fsstats1$indicatorword_token) 

save(fsstats1, file="rpackage/data/fsstats1.rda")
save(withindicator, file="rpackage/data/withindicator.rda")
