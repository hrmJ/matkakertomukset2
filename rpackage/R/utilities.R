
#' Convinience function for formatting numbers
#' @param n the number to print
#' @param numbers how many numbers after comma when rounding (in case of decimal numbers)
#' @return a string representing the number in a formatted name
#' @export

fn <- function(n,numbers=2){
    numstring <- formatC(round(n,numbers),numbers,format="f")
    return(gsub('\\.',',',numstring))
}

#' Just a convinience function for outputting to the right folder
#' 
#' @importFrom rmarkdown render
#' @param odir the folder to output to, defaults to "output"
#' @param fname name of the file to output (defaults to "koko_artikkeli.Rmd")
#' @export

Output <- function(odir="output",fname="koko_artikkeli.Rmd"){
    render(fname,output_dir=odir)
}

