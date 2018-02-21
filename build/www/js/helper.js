function select_option(s, i) {
    var option = $('#' + s + ' option[value="' + i + '"]');
    option.attr('selected', 'selected');
    $('select').material_select();
}

function string_of_enum(enum_var, value)
{
  for (var k in enum_var) if (enum_var[k] == value) return k;
  return null;
}

function val_of_enum(enum_var, string)
{
  for (var k in enum_var) if (k == string) return enum_var[k];
  return null;
}

$.fn.extend({
    animateCss: function (animationName, doAfter) {
        var animationEnd = 'webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend';
        this.addClass('animated ' + animationName).one(animationEnd, function() {
            $(this).removeClass('animated ' + animationName);
            if (doAfter != undefined) doAfter();
        });
    }
});
