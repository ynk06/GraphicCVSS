$(function () {
    $("#vendor_input").autocomplete({
        source: function (request, response) {
            var list = [];
            list = vendorlists.filter(function (word) {
                return word.indexOf(request.term) === 0 || word.toLowerCase().indexOf(request.term) === 0;
            }).slice(0, 10);
            response(list);
        },
    });
});