﻿namespace Core.Utilites.Results.Abstract
{
    public interface IDataResult<T> : IResult
    {
        T Response { get; }
    }
}
