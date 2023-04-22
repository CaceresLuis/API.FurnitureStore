namespace API.FurnitureStore.Shared.Common
{
    public static class RandomGenerator
    {
        public static string GenerateRandomString(int size)
        {
            Random ramdom = new Random();
            string chars = "ABCDEFGHYJKLMNOPQRSTUVWXYZabcdefghyjklmnopqrstuvwxyz$@#!%.,/-+_";

            return new string(Enumerable.Repeat(chars, size).Select(s => s[ramdom.Next(s.Length)]).ToArray());
        }
    }
}
