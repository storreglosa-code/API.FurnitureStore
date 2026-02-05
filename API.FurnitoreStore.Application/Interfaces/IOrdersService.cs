using System.Collections.Generic;
using System.Threading.Tasks;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Interfaces
{
    public interface IOrdersService
    {
        Task<IEnumerable<Order>> GetAllAsync();
        Task<Order?> GetByIdAsync(int id);
        Task CreateAsync(Order order);
        Task UpdateAsync(Order order);
        Task DeleteAsync(int id);
    }
}
