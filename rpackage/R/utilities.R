
#' Convinience function for formatting numbers
#' @param n the number to print
#' @param numbers how many numbers after comma when rounding (in case of decimal numbers)
#' @return a string representing the number in a formatted name
#' @export

fn <- function(n,numbers=2){
    numstring <- formatC(round(n,numbers),numbers,format="f")
    return(gsub('\\.',',',numstring))
}
