namespace SecurityTool.Shared
{
    public class PasswordResponse
    {
        public string ErrorMessage { get; set; }
        public bool? IsMatch { get; set; }

        public PasswordResponse( bool? isMatch, string errorMessage)
        {
            ErrorMessage = errorMessage;
            IsMatch = isMatch;
        }
    }
}
