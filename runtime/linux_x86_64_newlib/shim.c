extern int *__errno();

int *__errno_location(void)
{
    return __errno();
}