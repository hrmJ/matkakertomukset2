
#' Hae data ryhmistä yaml-tiedostojen perusteella
#' @export

GetGroupsFromYaml <- function(){

    grouplist <- lapply(list.files("data/groups/"),function(x)return(yaml.load(x)))

}
